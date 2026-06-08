# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the scan orchestrator (CLI_6, CLI_7, CLI_8).

Exercises scanner *mechanics* over controlled tmp_path inputs: per-file
isolation, severity filtering, deterministic dedup + total-order sort, and exit
code computation. Whole-fixtures-tree golden snapshots are Phase-5/WP-G, not here.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from scanipy.config import ScanConfig
from scanipy.exit_codes import ExitCode
from scanipy.models import Finding, Location, Severity, WitnessRole, WitnessStep
from scanipy.registry import load_builtin_detectors
from scanipy.scanner import aggregate, compute_exit_code, run_scan

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


def _finding(line: int, *, detector: str = "d", sev: Severity = Severity.HIGH) -> Finding:
    sink = Location(file="f.py", line=line, column=0)
    source = Location(file="f.py", line=line - 1, column=0)
    return Finding(
        detector_id=detector,
        cwe="CWE-1",
        severity=sev,
        message="m",
        location=sink,
        witness=(
            WitnessStep(role=WitnessRole.SOURCE, location=source),
            WitnessStep(role=WitnessRole.SINK, location=sink),
        ),
        fingerprint=f"fp-{detector}-{line}",
    )


# ---------------------------------------------------------------------------
# run_scan over real frontend + engine
# ---------------------------------------------------------------------------


def test_run_scan_flags_vulnerable(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(VULN)
    result = run_scan(tmp_path, load_builtin_detectors(), ScanConfig())
    assert result.exit_code is ExitCode.FINDINGS
    assert len(result.findings) == 1
    assert result.findings[0].cwe == "CWE-78"
    assert result.files_scanned == 1
    assert result.parse_errors == ()


def test_run_scan_clean_on_safe(tmp_path: Path) -> None:
    (tmp_path / "s.py").write_text(SAFE)
    result = run_scan(tmp_path, load_builtin_detectors(), ScanConfig())
    assert result.exit_code is ExitCode.OK
    assert result.findings == ()


def test_per_file_isolation_one_bad_file_does_not_abort(tmp_path: Path) -> None:
    (tmp_path / "good.py").write_text(VULN)
    (tmp_path / "broken.py").write_text("def f(:\n")  # syntax error
    result = run_scan(tmp_path, load_builtin_detectors(), ScanConfig())
    # The good file still produced its finding; the bad file is a reported error.
    assert any(f.cwe == "CWE-78" for f in result.findings)
    assert len(result.parse_errors) == 1
    assert result.parse_errors[0].path.name == "broken.py"
    assert result.diagnostics  # surfaced for stderr


def test_exclude_skips_file(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(VULN)
    config = ScanConfig(exclude=("v.py",))
    result = run_scan(tmp_path, load_builtin_detectors(), config)
    assert result.findings == ()
    assert result.files_scanned == 0


def test_run_scan_is_deterministic(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(VULN)
    first = run_scan(tmp_path, load_builtin_detectors(), ScanConfig())
    second = run_scan(tmp_path, load_builtin_detectors(), ScanConfig())
    assert [f.to_dict() for f in first.findings] == [f.to_dict() for f in second.findings]


# ---------------------------------------------------------------------------
# aggregate: severity filter + dedup + sort
# ---------------------------------------------------------------------------


def test_aggregate_filters_below_threshold() -> None:
    findings = [
        _finding(5, sev=Severity.LOW),
        _finding(6, sev=Severity.HIGH),
    ]
    kept = aggregate(findings, Severity.HIGH)
    assert len(kept) == 1
    assert kept[0].severity is Severity.HIGH


def test_aggregate_sorts_total_order() -> None:
    findings = [
        _finding(9, detector="b"),
        _finding(2, detector="a"),
        _finding(2, detector="c"),
    ]
    kept = aggregate(findings, Severity.LOW)
    lines = [(f.location.line, f.detector_id) for f in kept]
    assert lines == [(2, "a"), (2, "c"), (9, "b")]


def test_aggregate_dedups_same_finding() -> None:
    a = _finding(5, detector="x")
    b = _finding(5, detector="x")  # same detector + sink + source location
    kept = aggregate([a, b], Severity.LOW)
    assert len(kept) == 1


def test_aggregate_keeps_distinct_detectors_at_same_sink() -> None:
    a = _finding(5, detector="x")
    b = _finding(5, detector="y")
    kept = aggregate([a, b], Severity.LOW)
    assert len(kept) == 2


# ---------------------------------------------------------------------------
# compute_exit_code
# ---------------------------------------------------------------------------


def test_exit_zero_when_no_findings() -> None:
    assert compute_exit_code([], ScanConfig()) is ExitCode.OK


def test_exit_one_with_default_gate_any_finding() -> None:
    assert compute_exit_code([_finding(5, sev=Severity.LOW)], ScanConfig()) is ExitCode.FINDINGS


def test_fail_on_gate_above_finding_exits_zero() -> None:
    config = ScanConfig(fail_on=Severity.CRITICAL)
    assert compute_exit_code([_finding(5, sev=Severity.HIGH)], config) is ExitCode.OK


def test_fail_on_gate_met_exits_one() -> None:
    config = ScanConfig(fail_on=Severity.HIGH)
    assert compute_exit_code([_finding(5, sev=Severity.HIGH)], config) is ExitCode.FINDINGS


def test_gate_falls_back_to_threshold_when_no_fail_on() -> None:
    config = ScanConfig(severity_threshold=Severity.CRITICAL)
    # A HIGH finding is below the threshold gate -> clean exit.
    assert compute_exit_code([_finding(5, sev=Severity.HIGH)], config) is ExitCode.OK
