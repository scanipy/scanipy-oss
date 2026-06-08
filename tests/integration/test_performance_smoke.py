# SPDX-License-Identifier: Apache-2.0
"""Performance smoke test (QA_18).

Generates a synthetic corpus of ~50 files that exercise the analysis features
most prone to blowup — deep attribute chains and (mutual) recursion that drive
the summary fixpoint — and asserts the full scan finishes under a *generous*
wall-clock budget and produces a *deterministic* finding count.

This is not a benchmark. Its job is to catch an accidental loss of a depth /
fixpoint cap (which turns the analysis quadratic-to-exponential), so the budget
is deliberately loose to stay non-flaky on a busy CI runner.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from scanipy.config import ScanConfig
from scanipy.registry import load_builtin_detectors
from scanipy.scanner import run_scan

pytestmark = pytest.mark.integration

NUM_FILES = 50
TIME_BUDGET_SECONDS = 30.0


def _deep_chain_file(index: int) -> str:
    # A vulnerable os-command flow behind a long attribute chain + helper calls.
    return f"""
import os


class Box:
    def __init__(self, inner):
        self.inner = inner


def layer{index}_d(value):
    return value


def layer{index}_c(value):
    return layer{index}_d(value)


def layer{index}_b(value):
    return layer{index}_c(value)


def layer{index}_a(value):
    return layer{index}_b(value)


def handler{index}():
    raw = input()
    box = Box(Box(Box(raw)))
    tainted = layer{index}_a(box.inner.inner.inner)
    os.system("echo " + tainted)
"""


def _recursive_file(index: int) -> str:
    # Self-recursion and mutual recursion to drive the summary fixpoint cap.
    return f"""
import os


def recurse{index}(value, depth):
    if depth <= 0:
        return value
    return recurse{index}(value, depth - 1)


def ping{index}(value, depth):
    if depth <= 0:
        return value
    return pong{index}(value, depth - 1)


def pong{index}(value, depth):
    if depth <= 0:
        return value
    return ping{index}(value, depth - 1)


def run{index}():
    raw = input()
    passed = recurse{index}(raw, 5)
    bounced = ping{index}(passed, 5)
    os.system("echo " + bounced)
"""


def _build_synthetic_corpus(root: Path) -> int:
    for i in range(NUM_FILES):
        builder = _deep_chain_file if i % 2 == 0 else _recursive_file
        (root / f"mod_{i:03d}.py").write_text(builder(i))
    return NUM_FILES


def test_performance_smoke_bounded_and_deterministic(tmp_path: Path) -> None:
    written = _build_synthetic_corpus(tmp_path)
    assert written == NUM_FILES

    specs = load_builtin_detectors()
    config = ScanConfig()

    start = time.perf_counter()
    first = run_scan(tmp_path, specs, config)
    elapsed = time.perf_counter() - start

    assert elapsed < TIME_BUDGET_SECONDS, (
        f"scan of {NUM_FILES} synthetic files took {elapsed:.1f}s "
        f"(budget {TIME_BUDGET_SECONDS}s) — possible fixpoint/depth blowup"
    )
    assert first.files_scanned == NUM_FILES

    # Deterministic finding count: a second run produces the identical total.
    second = run_scan(tmp_path, specs, config)
    assert len(first.findings) == len(second.findings)
    # Every generated module carries a reachable os-command flow.
    assert len(first.findings) >= NUM_FILES
