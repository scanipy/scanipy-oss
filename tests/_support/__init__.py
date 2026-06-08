# SPDX-License-Identifier: Apache-2.0
"""Shared test-support helpers for the scanipy QA suite.

This package is intentionally tiny and dependency-free (stdlib + scanipy only).
It holds the pieces that more than one cross-cutting suite needs:

* :mod:`tests._support.normalize` — version/path-tolerant normalizers used by the
  golden-snapshot and determinism suites so committed snapshots never embed a
  machine path or the embedded tool version.
* :mod:`tests._support.corpus` — a deterministic, copied scan corpus and the
  single ``run_corpus_scan`` entry point shared by golden + determinism + perf.
"""
