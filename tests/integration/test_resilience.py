# SPDX-License-Identifier: Apache-2.0
"""Resilience to unparsable / non-UTF-8 inputs (QA_17, P7).

A scan over a tree that mixes valid code with a Python ``SyntaxError`` file and a
non-UTF-8 / binary ``.py`` file must:

* complete successfully (never crash),
* still scan the valid files and report their findings,
* record the bad files as **skipped diagnostics** (not exceptions), and
* return OK / FINDINGS — *not* ERROR — because bad inputs are expected, not a
  usage error. A genuinely missing path is the one case that is a usage ERROR(2).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from scanipy.cli import cli
from scanipy.config import ScanConfig
from scanipy.exit_codes import ExitCode
from scanipy.registry import load_builtin_detectors
from scanipy.scanner import run_scan

pytestmark = pytest.mark.integration

_VULN = textwrap.dedent(
    """
    import os

    def main():
        name = input()
        os.system("echo " + name)
    """
)
_SAFE = textwrap.dedent(
    """
    def add(a, b):
        return a + b
    """
)
_SYNTAX_ERROR = "def f(:\n    pass\n"
_NON_UTF8 = b"x = 1\n\xff\xfe not valid utf-8 \x80\x81\n"


def _build_mixed_tree(root: Path) -> None:
    (root / "good_vuln.py").write_text(_VULN)
    (root / "good_safe.py").write_text(_SAFE)
    (root / "broken_syntax.py").write_text(_SYNTAX_ERROR)
    (root / "binary.py").write_bytes(_NON_UTF8)


def test_scanner_completes_and_skips_bad_files(tmp_path: Path) -> None:
    _build_mixed_tree(tmp_path)
    result = run_scan(tmp_path, load_builtin_detectors(), ScanConfig())

    # The valid vulnerable file was still scanned and flagged.
    assert any(f.detector_id == "python.injection.os-command" for f in result.findings)

    # Both bad files are recorded as skipped diagnostics, not raised.
    bad_paths = {Path(err.path).name for err in result.parse_errors}
    assert bad_paths == {"broken_syntax.py", "binary.py"}

    # Exit code reflects the real findings, never ERROR.
    assert result.exit_code is ExitCode.FINDINGS


def test_scanner_only_bad_files_is_clean_not_error(tmp_path: Path) -> None:
    (tmp_path / "broken_syntax.py").write_text(_SYNTAX_ERROR)
    (tmp_path / "binary.py").write_bytes(_NON_UTF8)
    result = run_scan(tmp_path, load_builtin_detectors(), ScanConfig())

    assert result.findings == ()
    assert len(result.parse_errors) == 2
    # No valid findings and no usage error: OK, not ERROR.
    assert result.exit_code is ExitCode.OK


def test_cli_returns_findings_not_error_on_mixed_tree(runner: CliRunner, tmp_path: Path) -> None:
    _build_mixed_tree(tmp_path)
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    # FINDINGS (1), not ERROR (2): bad files are diagnosed, not fatal.
    assert result.exit_code == int(ExitCode.FINDINGS)
    assert "python.injection.os-command" in result.output


def test_cli_returns_ok_when_only_bad_files(runner: CliRunner, tmp_path: Path) -> None:
    (tmp_path / "broken_syntax.py").write_text(_SYNTAX_ERROR)
    (tmp_path / "binary.py").write_bytes(_NON_UTF8)
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == int(ExitCode.OK)


def test_cli_missing_path_is_usage_error(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(cli, ["scan", str(tmp_path / "does-not-exist")])
    assert result.exit_code == int(ExitCode.ERROR)
