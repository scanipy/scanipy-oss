# SPDX-License-Identifier: Apache-2.0
"""Cross-cutting determinism guarantees over the real pipeline (QA_15, P3).

The engine-level determinism unit tests already cover repeated single-file
analysis and spec-order shuffling. This integration suite pins the *pipeline*
guarantees that users actually observe:

* scanning a representative corpus twice yields **byte-identical JSON**, and
* **byte-identical SARIF**, and
* the order in which input files are fed to the engine does not change the final
  sorted finding set (the total order is real, not an artifact of discovery's
  internal sort).
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest
from tests._support.corpus import build_corpus, corpus_findings

from scanipy.discovery import discover_python_files
from scanipy.engine import TaintEngine
from scanipy.frontends.python_frontend import PythonFrontend
from scanipy.models import Finding, Severity
from scanipy.registry import load_builtin_detectors
from scanipy.reporting import get_reporter
from scanipy.scanner import aggregate

pytestmark = pytest.mark.integration


def test_corpus_scan_twice_is_byte_identical_json(tmp_path: Path) -> None:
    corpus = build_corpus(tmp_path)
    first = get_reporter("json").render(corpus_findings(corpus))
    second = get_reporter("json").render(corpus_findings(corpus))
    assert first == second


def test_corpus_scan_twice_is_byte_identical_sarif(tmp_path: Path) -> None:
    corpus = build_corpus(tmp_path)
    first = get_reporter("sarif").render(corpus_findings(corpus))
    second = get_reporter("sarif").render(corpus_findings(corpus))
    assert first == second


def _findings_with_file_order(files: list[Path]) -> tuple[Finding, ...]:
    """Analyze ``files`` in the given order and aggregate into the total order."""
    engine = TaintEngine(load_builtin_detectors())
    frontend = PythonFrontend()
    raw: list[Finding] = []
    for file in files:
        module = frontend.parse(file)
        assert module is not None
        raw.extend(engine.analyze(module))
    return aggregate(raw, Severity.LOW)


def test_shuffled_input_order_yields_identical_sorted_findings(tmp_path: Path) -> None:
    corpus = build_corpus(tmp_path)
    files = list(discover_python_files(corpus))
    assert len(files) > 1

    baseline = _findings_with_file_order(files)

    for seed in (1, 7, 42, 1234):
        shuffled = files[:]
        random.Random(seed).shuffle(shuffled)
        assert _findings_with_file_order(shuffled) == baseline, (
            f"finding order depended on input-file order (seed={seed})"
        )


def test_shuffled_order_matches_run_scan(tmp_path: Path) -> None:
    # The shuffle-invariant aggregate must agree with the scanner's own output.
    corpus = build_corpus(tmp_path)
    files = list(discover_python_files(corpus))
    shuffled = files[:]
    random.Random(99).shuffle(shuffled)
    assert _findings_with_file_order(shuffled) == corpus_findings(corpus)
