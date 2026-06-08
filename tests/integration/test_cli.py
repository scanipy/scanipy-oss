# SPDX-License-Identifier: Apache-2.0
"""Integration tests for the CLI (CLI_9, CLI_10, CLI_11) via CliRunner.

Drives ``scanipy scan`` and ``scanipy rules`` over controlled tmp_path inputs (a
known tiny vulnerable snippet and a safe one) and asserts specific findings, exit
codes, output formats, excludes, config precedence, rules behavior, and that no
network access happens (socket guard). The existing os-command fixture is used for
a single happy-path e2e asserting the specific finding (not a whole-tree count).
"""

from __future__ import annotations

import json
import socket
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest
from click.testing import CliRunner

from scanipy.cli import cli

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
OS_COMMAND_VULN = REPO_ROOT / "tests" / "fixtures" / "python" / "vulnerable" / "os-command.py"

VULN = textwrap.dedent(
    """
    import os

    def main():
        name = input()
        os.system("echo " + name)
    """
)

SAFE = textwrap.dedent(
    """
    import shlex
    import subprocess

    def main():
        name = input()
        subprocess.run(["echo", shlex.quote(name)], check=True)
    """
)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail loudly if the scan path opens a socket (P1: local & private)."""

    def _blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network access attempted during scan (violates P1)")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    yield


def _write(tmp_path: Path, name: str, content: str) -> Path:
    f = tmp_path / name
    f.write_text(content)
    return f


# ---------------------------------------------------------------------------
# scan: findings + exit codes
# ---------------------------------------------------------------------------


def test_scan_vulnerable_exits_one_with_finding(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "python.injection.os-command" in result.output
    assert "CWE-78" in result.output


def test_scan_safe_exits_zero(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "s.py", SAFE)
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No findings." in result.output


def test_scan_zero_config_works(runner: CliRunner, tmp_path: Path) -> None:
    # No config file present; defaults must still produce a finding (P6).
    _write(tmp_path, "v.py", VULN)
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 1


def test_scan_e2e_os_command_fixture_specific_finding(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["scan", str(OS_COMMAND_VULN), "--format", "json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    cwe78 = [f for f in payload["findings"] if f["detector_id"] == "python.injection.os-command"]
    assert len(cwe78) == 1
    assert cwe78[0]["cwe"] == "CWE-78"
    assert cwe78[0]["location"]["line"] == 10  # os.system(...)
    assert cwe78[0]["witness"][0]["role"] == "source"
    assert cwe78[0]["witness"][-1]["role"] == "sink"


def test_scan_nonexistent_path_exits_two(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(cli, ["scan", str(tmp_path / "nope")])
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# scan: output formats
# ---------------------------------------------------------------------------


def test_scan_json_is_valid_and_machine_clean(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    _write(tmp_path, "broken.py", "def f(:\n")  # parse error -> stderr only
    result = runner.invoke(cli, ["scan", str(tmp_path), "--format", "json"])
    # stdout must be parseable JSON even with a broken file in the tree.
    payload = json.loads(result.stdout)
    assert payload["tool"] == "scanipy"
    assert any(f["cwe"] == "CWE-78" for f in payload["findings"])
    # The parse-error diagnostic went to stderr, never stdout.
    assert "warning" in result.stderr
    assert "warning" not in result.stdout


def test_scan_sarif_is_valid(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    result = runner.invoke(cli, ["scan", str(tmp_path), "--format", "sarif"])
    payload = json.loads(result.stdout)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"]


def test_scan_output_file(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    out = tmp_path / "report.json"
    result = runner.invoke(cli, ["scan", str(tmp_path), "--format", "json", "-o", str(out)])
    assert result.exit_code == 1
    assert out.exists()
    payload = json.loads(out.read_text())
    assert any(f["cwe"] == "CWE-78" for f in payload["findings"])


def test_scan_output_deterministic(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    first = runner.invoke(cli, ["scan", str(tmp_path), "--format", "json"])
    second = runner.invoke(cli, ["scan", str(tmp_path), "--format", "json"])
    assert first.stdout == second.stdout


# ---------------------------------------------------------------------------
# scan: severity, fail-on, excludes, detectors
# ---------------------------------------------------------------------------


def test_scan_severity_threshold_filters(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    # os-command is HIGH; a critical threshold filters it out -> clean.
    result = runner.invoke(cli, ["scan", str(tmp_path), "--severity-threshold", "critical"])
    assert result.exit_code == 0
    assert "No findings." in result.output


def test_scan_fail_on_above_finding_exits_zero(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    # Reported (HIGH) but the fail gate is critical -> exit 0 though it prints.
    result = runner.invoke(cli, ["scan", str(tmp_path), "--fail-on", "critical"])
    assert result.exit_code == 0
    assert "python.injection.os-command" in result.output


def test_scan_exclude_glob(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    result = runner.invoke(cli, ["scan", str(tmp_path), "--exclude", "v.py"])
    assert result.exit_code == 0


def test_scan_unknown_detector_exits_two(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    result = runner.invoke(cli, ["scan", str(tmp_path), "--detectors", "nope.detector"])
    assert result.exit_code == 2
    assert "unknown detector" in result.output


def test_scan_detectors_filter_runs_only_selected(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    result = runner.invoke(
        cli,
        ["scan", str(tmp_path), "--detectors", "python.injection.sql", "--format", "json"],
    )
    payload = json.loads(result.stdout)
    # Only sql was requested; the os-command vuln is not reported.
    assert all(f["detector_id"] == "python.injection.sql" for f in payload["findings"])
    assert result.exit_code == 0  # no sql finding in this snippet


# ---------------------------------------------------------------------------
# scan: config file precedence (CLI > file > defaults)
# ---------------------------------------------------------------------------


def test_config_file_sets_threshold(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    _write(tmp_path, ".scanipy.yml", "severity_threshold: critical\n")
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0  # HIGH finding filtered by the file's threshold


def test_cli_overrides_config_file(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    _write(tmp_path, ".scanipy.yml", "severity_threshold: critical\n")
    result = runner.invoke(cli, ["scan", str(tmp_path), "--severity-threshold", "low"])
    assert result.exit_code == 1  # CLI low overrides the file's critical


def test_invalid_config_exits_two(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    _write(tmp_path, ".scanipy.yml", "bogus_key: 1\n")
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert "unknown config key" in result.output


def test_explicit_config_flag(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    cfg = _write(tmp_path, "custom.yml", "severity_threshold: critical\n")
    result = runner.invoke(cli, ["scan", str(tmp_path), "--config", str(cfg)])
    assert result.exit_code == 0


def test_config_file_exclude_honored_when_cli_silent(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    _write(tmp_path, ".scanipy.yml", 'exclude:\n  - "v.py"\n')
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0  # the file-configured exclude skipped the only vuln


def test_config_file_detectors_honored_when_cli_silent(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    _write(tmp_path, ".scanipy.yml", 'detectors:\n  - "python.injection.sql"\n')
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0  # only sql ran; the os-command vuln is unreported


def test_no_gitignore_flag_scans_ignored_files(runner: CliRunner, tmp_path: Path) -> None:
    _write(tmp_path, "v.py", VULN)
    _write(tmp_path, ".gitignore", "v.py\n")
    # Default honors .gitignore -> the vuln is skipped.
    default = runner.invoke(cli, ["scan", str(tmp_path)])
    assert default.exit_code == 0
    # --no-gitignore opts back in -> the vuln is found.
    opted = runner.invoke(cli, ["scan", str(tmp_path), "--no-gitignore"])
    assert opted.exit_code == 1


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------


def test_rules_list_sorted(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["rules", "list"])
    assert result.exit_code == 0
    ids = [line.split()[0] for line in result.output.splitlines() if line.strip()]
    assert ids == sorted(ids)
    assert "python.injection.os-command" in ids


def test_rules_show_known(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["rules", "show", "python.injection.os-command"])
    assert result.exit_code == 0
    assert "CWE-78" in result.output
    assert "sources:" in result.output
    assert "sinks:" in result.output


def test_rules_show_unknown_exits_two(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["rules", "show", "python.nope.nope"])
    assert result.exit_code == 2
    assert "unknown detector id" in result.output
    assert "python.injection.os-command" in result.output  # lists available ids


def test_rules_validate_valid(runner: CliRunner, tmp_path: Path) -> None:
    spec = REPO_ROOT / "tests" / "fixtures" / "dsl" / "valid" / "minimal.yml"
    result = runner.invoke(cli, ["rules", "validate", str(spec)])
    assert result.exit_code == 0
    assert "valid" in result.output


def test_rules_validate_invalid_exits_two(runner: CliRunner) -> None:
    spec = REPO_ROOT / "tests" / "fixtures" / "dsl" / "invalid" / "bad-cwe.yml"
    result = runner.invoke(cli, ["rules", "validate", str(spec)])
    assert result.exit_code == 2
    # DSLError message is surfaced.
    assert "cwe" in result.output.lower()
