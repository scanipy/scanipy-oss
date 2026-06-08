# SPDX-License-Identifier: Apache-2.0
"""DOCS_TEST_3 — docs <-> catalog bijection (H green).

Every detector id and CWE in the shipped catalog must be documented, and every
detector id the docs mention must be a real bundled spec — no phantom, no
undocumented, no stale CWE. Concretely:

* **CHANGELOG.md** documents the full catalog: every real detector ``id`` (with
  its ``CWE-NNN``) appears, and every ``python.*`` id the CHANGELOG mentions is a
  real spec (full bijection on ids).
* **README.md** mentions only real detector ids (no phantom entries); it need not
  list all seven, but every id it does list must exist.

The real catalog is read from the loaded bundled specs (the single source of
truth), not re-listed here. Hermetic: reads repo files + the in-process registry.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanipy.registry import load_builtin_detectors

REPO_ROOT = Path(__file__).resolve().parents[2]
README = REPO_ROOT / "README.md"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"

# A detector id: anchored on the language prefix so dotted *patterns* like
# "os.system" or "flask.request.*" are never mistaken for ids.
_ID_RE = re.compile(r"\bpython\.[a-z0-9]+(?:[.-][a-z0-9]+)+\b")


def _catalog() -> dict[str, str]:
    """Real shipped catalog: detector id -> CWE (from the loaded bundled specs)."""
    return {spec.id: spec.cwe for spec in load_builtin_detectors()}


def _ids_in(text: str) -> set[str]:
    return set(_ID_RE.findall(text))


def test_catalog_is_nonempty() -> None:
    # Guards against the regex/loader silently matching nothing.
    catalog = _catalog()
    assert len(catalog) == 7, f"expected 7 bundled detectors, found {sorted(catalog)}"


def test_changelog_documents_every_detector_id_and_cwe() -> None:
    catalog = _catalog()
    text = CHANGELOG.read_text(encoding="utf-8")
    for detector_id, cwe in sorted(catalog.items()):
        assert detector_id in text, f"CHANGELOG.md does not document detector id {detector_id!r}"
        assert cwe in text, f"CHANGELOG.md does not mention {cwe} (for {detector_id})"


def test_changelog_mentions_no_phantom_detectors() -> None:
    catalog = _catalog()
    mentioned = _ids_in(CHANGELOG.read_text(encoding="utf-8"))
    phantom = mentioned - set(catalog)
    assert not phantom, f"CHANGELOG.md mentions detector ids that do not exist: {sorted(phantom)}"


def test_changelog_id_bijection() -> None:
    # Both directions on CHANGELOG ids: documented == real.
    catalog_ids = set(_catalog())
    mentioned = _ids_in(CHANGELOG.read_text(encoding="utf-8"))
    assert mentioned == catalog_ids, (
        f"CHANGELOG ids and catalog ids diverge: "
        f"only in changelog={sorted(mentioned - catalog_ids)}, "
        f"only in catalog={sorted(catalog_ids - mentioned)}"
    )


def test_readme_mentions_no_phantom_detectors() -> None:
    catalog = _catalog()
    mentioned = _ids_in(README.read_text(encoding="utf-8"))
    phantom = mentioned - set(catalog)
    assert not phantom, f"README.md mentions detector ids that do not exist: {sorted(phantom)}"


def test_readme_documents_at_least_one_real_detector() -> None:
    catalog = _catalog()
    mentioned = _ids_in(README.read_text(encoding="utf-8"))
    assert mentioned & set(catalog), "README.md should reference at least one real detector id"
