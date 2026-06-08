# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for the 0.1.0 CLI skeleton.

These assert the contract the scaffold guarantees today: help and version work
and exit 0; the not-yet-implemented commands exit with ExitCode.ERROR (2).
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


def test_scan_is_stubbed(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 2


def test_rules_list_is_stubbed(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["rules", "list"])
    assert result.exit_code == 2


def test_rules_validate_is_stubbed(runner: CliRunner, tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text("id: example\n")
    result = runner.invoke(cli, ["rules", "validate", str(spec)])
    assert result.exit_code == 2
