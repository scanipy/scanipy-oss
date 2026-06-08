# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for the CLI surface.

These assert the always-on contract: help and version exit 0, a bare invocation
prints usage, and ``scan`` / ``rules`` are now real commands (no longer stubs).
The full behavioral matrix (findings, exit codes, formats, config precedence)
lives in ``tests/integration/test_cli.py``.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from scanipy import __version__
from scanipy.cli import cli


def test_help_exits_zero(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "scanipy" in result.output


def test_bare_invocation_shows_help(runner: CliRunner) -> None:
    # No subcommand prints help (a usage signal) and exits non-zero.
    result = runner.invoke(cli, [])
    assert result.exit_code == 2
    assert "Usage" in result.output
    assert "Commands" in result.output


def test_version_command(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_version_flag(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_scan_empty_dir_is_clean(runner: CliRunner, tmp_path: Path) -> None:
    # scan is real now: an empty directory has no findings and exits 0.
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No findings." in result.output


def test_rules_list_is_real(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["rules", "list"])
    assert result.exit_code == 0
    assert "python.injection.os-command" in result.output


def test_rules_validate_rejects_bad_spec(runner: CliRunner, tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text("id: example\n")  # missing required fields
    result = runner.invoke(cli, ["rules", "validate", str(spec)])
    assert result.exit_code == 2
