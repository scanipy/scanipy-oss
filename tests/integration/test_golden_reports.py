# SPDX-License-Identifier: Apache-2.0
"""Golden-snapshot regression tests for the JSON and SARIF reporters (QA_16).

Scans a fixed corpus (the vulnerable + safe fixture trees) with the full bundled
detector pack, renders JSON and SARIF, normalizes the output (version, machine
paths, and the path-derived witness fingerprint), and compares it to the snapshot
committed under ``tests/golden/``.

The snapshots are normalized *on disk* so they never contain a machine path or
the embedded tool version, which means a version bump or a different CI runner
does not spuriously break them while a real change to the findings still does.

Regenerate after an intentional change with::

    SCANIPY_UPDATE_GOLDEN=1 pytest tests/integration/test_golden_reports.py

(see ``docs/testing.md``).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from tests._support.corpus import build_corpus, corpus_findings
from tests._support.normalize import (
    dumps_canonical,
    normalize_json_report,
    normalize_sarif,
)

from scanipy.reporting import get_reporter

# The golden encodes exact AST positions (columns / end-positions). CPython does
# not guarantee byte-identical positions across versions (e.g. PEP 701 shifted
# f-string positions in 3.12), so the snapshot is pinned to the interpreter it is
# generated on (3.12) and the comparison is skipped elsewhere. Within-version
# nondeterminism is still caught on every 3.10-3.13 matrix entry by the
# determinism suite (scan-twice + input-order shuffle); goldens are deliberately
# version-pinned regression artifacts.
_GOLDEN_PYTHON = (3, 12)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.version_info[:2] != _GOLDEN_PYTHON,
        reason="golden snapshot is pinned to the generating interpreter's AST positions",
    ),
]

GOLDEN_DIR = Path(__file__).resolve().parents[1] / "golden"
GOLDEN_JSON = GOLDEN_DIR / "scan-corpus.json"
# Stored with a ``.sarif.json`` suffix (SARIF is JSON) so the repo-wide
# ``*.sarif`` gitignore — meant for transient scan output — does not swallow this
# committed test artifact.
GOLDEN_SARIF = GOLDEN_DIR / "scan-corpus.sarif.json"

_UPDATE = os.environ.get("SCANIPY_UPDATE_GOLDEN") == "1"


def _normalized_outputs(tmp_path: Path) -> tuple[str, str]:
    corpus = build_corpus(tmp_path)
    findings = corpus_findings(corpus)
    json_text = dumps_canonical(
        normalize_json_report(get_reporter("json").render(findings), corpus)
    )
    sarif_text = dumps_canonical(normalize_sarif(get_reporter("sarif").render(findings), corpus))
    return json_text, sarif_text


def _check_or_update(actual: str, golden_path: Path) -> None:
    if _UPDATE:
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(actual, encoding="utf-8")
        pytest.skip(f"updated golden {golden_path.name} (SCANIPY_UPDATE_GOLDEN=1)")
    assert golden_path.exists(), (
        f"missing golden {golden_path}; regenerate with SCANIPY_UPDATE_GOLDEN=1"
    )
    expected = golden_path.read_text(encoding="utf-8")
    assert actual == expected, (
        f"{golden_path.name} drifted from the committed snapshot; "
        f"if this change is intentional, regenerate with SCANIPY_UPDATE_GOLDEN=1"
    )


def test_json_report_matches_golden(tmp_path: Path) -> None:
    json_text, _ = _normalized_outputs(tmp_path)
    _check_or_update(json_text, GOLDEN_JSON)


def test_sarif_report_matches_golden(tmp_path: Path) -> None:
    _, sarif_text = _normalized_outputs(tmp_path)
    _check_or_update(sarif_text, GOLDEN_SARIF)
