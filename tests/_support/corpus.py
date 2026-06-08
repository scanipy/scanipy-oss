# SPDX-License-Identifier: Apache-2.0
"""The shared scan corpus for golden, determinism, and performance suites.

A single, deliberate definition of "the corpus" keeps the cross-cutting suites
honest: golden snapshots, the byte-identical determinism asserts, and the
end-to-end scans all run the *same* files through the *same* real pipeline
(``scanipy.scanner.run_scan`` over the bundled detector pack).

The corpus is the ``vulnerable/`` and ``safe/`` fixture trees only. The
``ir/`` tree (which holds an intentional ``SyntaxError`` file and a binary
``.bin``) is deliberately excluded here so the golden snapshot stays a clean
findings document; resilience to those bad inputs is exercised separately in
``tests/integration/test_resilience.py``.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from scanipy.config import ScanConfig
from scanipy.models import Finding
from scanipy.registry import load_builtin_detectors
from scanipy.scanner import ScanResult, run_scan

FIXTURES_PYTHON = Path(__file__).resolve().parents[1] / "fixtures" / "python"
_CORPUS_SUBTREES = ("vulnerable", "safe")


def build_corpus(dest_root: Path) -> Path:
    """Copy the vulnerable+safe fixture trees into ``dest_root/corpus`` and return it.

    Copying into a tmp dir gives every test a stable, isolated path whose absolute
    file locations are normalizable (see :mod:`tests._support.normalize`).
    """
    corpus = dest_root / "corpus"
    corpus.mkdir(parents=True, exist_ok=True)
    for sub in _CORPUS_SUBTREES:
        shutil.copytree(FIXTURES_PYTHON / sub, corpus / sub)
    return corpus


def scan_corpus(corpus_root: Path) -> ScanResult:
    """Run the real scanner over ``corpus_root`` with the full bundled detector pack."""
    return run_scan(corpus_root, load_builtin_detectors(), ScanConfig())


def corpus_findings(corpus_root: Path) -> tuple[Finding, ...]:
    """The sorted findings the full pack produces over the corpus (single source)."""
    return scan_corpus(corpus_root).findings
