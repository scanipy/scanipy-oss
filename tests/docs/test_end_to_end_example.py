# SPDX-License-Identifier: Apache-2.0
"""DOCS_TEST_2 — the end-to-end example matches real CLI output (H green).

``docs/examples/end-to-end.md`` shows the exact ``scanipy scan`` output for the
``os-command`` vulnerable/safe fixture pair. This drives the **real CLI** (via
CliRunner, from the repo root so the echoed relative paths are stable) and asserts
both directions:

1. the live output and exit code are what we expect, and
2. that exact output appears verbatim in the committed doc.

Hermetic: CliRunner in-process, a socket guard (P1), no subprocess.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path

import pytest
from click.testing import CliRunner

from scanipy.cli import cli

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC = REPO_ROOT / "docs" / "examples" / "end-to-end.md"

VULN_ARG = "tests/fixtures/python/vulnerable/os-command.py"
SAFE_ARG = "tests/fixtures/python/safe/os-command.py"

EXPECTED_VULN_OUTPUT = (
    "HIGH python.injection.os-command [CWE-78] "
    "tests/fixtures/python/vulnerable/os-command.py:10:4\n"
    "    Untrusted input reaches an OS command without sanitization, allowing an "
    "attacker to execute arbitrary commands. Prefer a list argv with shell=False, "
    "or quote inputs with shlex.quote.\n"
    "\n"
    "    - source: tests/fixtures/python/vulnerable/os-command.py:9:11  source input\n"
    "    - sink: tests/fixtures/python/vulnerable/os-command.py:10:4  sink os.system\n"
    "\n"
    "1 finding.\n"
)

EXPECTED_SAFE_OUTPUT = "No findings.\n"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail loudly if the scan path opens a socket (P1: local & private)."""

    def _blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network access attempted during scan (violates P1)")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    yield


@pytest.fixture(autouse=True)
def _at_repo_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run from the repo root so echoed relative paths are deterministic."""
    monkeypatch.chdir(REPO_ROOT)


def test_vulnerable_scan_matches_live_cli(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["scan", VULN_ARG])
    assert result.exit_code == 1
    assert result.output == EXPECTED_VULN_OUTPUT


def test_safe_scan_matches_live_cli(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["scan", SAFE_ARG])
    assert result.exit_code == 0
    assert result.output == EXPECTED_SAFE_OUTPUT


def test_doc_contains_live_vulnerable_output() -> None:
    doc = DOC.read_text(encoding="utf-8")
    assert EXPECTED_VULN_OUTPUT in doc, (
        "docs/examples/end-to-end.md no longer matches the real `scan` output for "
        "the vulnerable fixture"
    )


def test_doc_contains_live_safe_output() -> None:
    doc = DOC.read_text(encoding="utf-8")
    assert EXPECTED_SAFE_OUTPUT in doc, (
        "docs/examples/end-to-end.md no longer matches the real `scan` output for the safe fixture"
    )


def test_doc_states_exit_codes() -> None:
    doc = DOC.read_text(encoding="utf-8")
    # The doc must show the exit codes for both branches.
    assert "exits `1`" in doc
    assert "exits `0`" in doc
