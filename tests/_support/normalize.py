# SPDX-License-Identifier: Apache-2.0
"""Version- and path-tolerant normalizers for golden snapshots and determinism.

Both reporters embed :data:`scanipy.__version__` (and the locked DoD bumps it),
and findings carry absolute, machine-specific file paths under ``tmp_path``. A
committed golden snapshot must contain neither, or it would break on every
version bump and on every machine/CI runner.

These helpers parse the reporter output and rewrite:

* the embedded tool version -> the literal ``"<VERSION>"`` placeholder, and
* every file path that lives under ``corpus_root`` -> a stable, repo-relative
  POSIX path (``corpus/...``), so two scans from different working directories
  produce byte-identical normalized output.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

VERSION_PLACEHOLDER = "<VERSION>"
FINGERPRINT_PLACEHOLDER = "<FINGERPRINT>"
_CORPUS_PREFIX = "corpus"


def _relativize(path_value: str, corpus_root: Path) -> str:
    """Rewrite an absolute path under ``corpus_root`` to ``corpus/<rel>`` (POSIX).

    Paths that are not under ``corpus_root`` are returned unchanged so the
    normalizer never silently mangles unexpected output.
    """
    try:
        candidate = Path(path_value)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return path_value
    try:
        rel = candidate.resolve().relative_to(corpus_root.resolve())
    except ValueError:
        return path_value
    return f"{_CORPUS_PREFIX}/{rel.as_posix()}"


def normalize_json_report(text: str, corpus_root: Path) -> dict[str, Any]:
    """Normalize a :class:`~scanipy.reporting.json_reporter.JsonReporter` payload.

    Sets ``version`` to the placeholder, rewrites every finding/witness file path
    to a repo-relative POSIX path under ``corpus/``, and replaces the witness
    ``fingerprint`` with a placeholder.

    The fingerprint is a stable sha256 of the ordered ``(role, file, line, col)``
    witness tuples — deterministic *for a given absolute path* (the real P3
    guarantee, asserted directly in the determinism suite) but path-dependent by
    construction, so it cannot appear verbatim in a machine-independent golden.
    """
    payload: dict[str, Any] = json.loads(text)
    payload["version"] = VERSION_PLACEHOLDER
    for finding in payload.get("findings", []):
        if "fingerprint" in finding and finding["fingerprint"] is not None:
            finding["fingerprint"] = FINGERPRINT_PLACEHOLDER
        _normalize_location(finding.get("location"), corpus_root)
        for step in finding.get("witness", []):
            _normalize_location(step.get("location"), corpus_root)
    return payload


def _normalize_location(location: Any, corpus_root: Path) -> None:
    if isinstance(location, dict) and isinstance(location.get("file"), str):
        location["file"] = _relativize(location["file"], corpus_root)


def normalize_sarif(text: str, corpus_root: Path) -> dict[str, Any]:
    """Normalize a SARIF 2.1.0 log: driver version + repo-relative artifact URIs."""
    log: dict[str, Any] = json.loads(text)
    for run in log.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        if "version" in driver:
            driver["version"] = VERSION_PLACEHOLDER
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                artifact = loc.get("physicalLocation", {}).get("artifactLocation", {})
                if isinstance(artifact.get("uri"), str):
                    artifact["uri"] = _relativize(artifact["uri"], corpus_root)
    return log


def dumps_canonical(obj: Any) -> str:
    """Serialize a normalized object the way goldens are stored on disk (stable)."""
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"
