# SPDX-License-Identifier: Apache-2.0
"""Hermeticity guarantees: no network on the scan path, no subprocess in the suite.

* **No network (P1, local & private):** a scan never opens a socket. We monkeypatch
  every socket entry point to raise and confirm a full scan — over a corpus that
  *mentions* network sinks (the SSRF fixtures) — still completes and flags them.
* **No subprocess in the suite:** the test suite drives the CLI exclusively through
  ``click.testing.CliRunner`` (in-process), never a real child process. An AST
  meta-test enforces that no test module imports ``subprocess``.
* **I/O confinement:** product scans target a copied corpus / ``tmp_path`` only;
  this module's scans never touch the developer's working tree.
"""

from __future__ import annotations

import ast
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests._support.corpus import build_corpus

from scanipy.config import ScanConfig
from scanipy.registry import load_builtin_detectors
from scanipy.scanner import run_scan

pytestmark = pytest.mark.integration

TESTS_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def _no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make any socket use raise, so an accidental network call fails loudly."""

    def _blocked(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("network access attempted during scan (violates P1)")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    yield


def test_full_scan_makes_no_network_calls(_no_network: None, tmp_path: Path) -> None:
    corpus = build_corpus(tmp_path)
    result = run_scan(corpus, load_builtin_detectors(), ScanConfig())
    # The scan completed under the socket guard and still produced findings,
    # including the SSRF detector whose patterns name network calls.
    assert result.findings
    assert any(f.detector_id == "python.ssrf.ssrf" for f in result.findings)


def _imports_subprocess(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(a.name == "subprocess" or a.name.startswith("subprocess.") for a in node.names):
                return True
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            return True
    return False


def test_no_test_module_imports_subprocess() -> None:
    # Fixtures are analysis DATA (intentionally-vulnerable code) — exclude them.
    offenders = [
        str(p.relative_to(TESTS_ROOT))
        for p in TESTS_ROOT.rglob("*.py")
        if "fixtures" not in p.parts and _imports_subprocess(p)
    ]
    assert offenders == [], f"test modules must not spawn subprocesses (use CliRunner): {offenders}"


def test_scans_confined_to_tmp_path(tmp_path: Path) -> None:
    # Sanity guard that the corpus helper writes only under tmp_path.
    corpus = build_corpus(tmp_path)
    assert corpus.is_relative_to(tmp_path)
    for child in corpus.rglob("*"):
        assert child.is_relative_to(tmp_path)
