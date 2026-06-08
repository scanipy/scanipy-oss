# SPDX-License-Identifier: Apache-2.0
"""Targeted behavior tests for edge branches the broader suites do not hit.

These pin honest product behavior on narrow paths: config error/edge branches,
``load_config`` with an explicit path, the scanner's per-file analysis-failure
isolation, taint binding through unpacking/attribute/subscript targets, and the
``python -m scanipy`` entry point.
"""

from __future__ import annotations

import runpy
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from scanipy import config as config_mod
from scanipy.config import ConfigError, ScanConfig, load_config, load_file_config
from scanipy.dsl import DetectorSpec, Pattern, PatternKind
from scanipy.engine.taint import TaintEngine
from scanipy.frontends.python_frontend import PythonFrontend
from scanipy.models import Finding, Severity
from scanipy.scanner import ScanConfig as ScannerScanConfig
from scanipy.scanner import run_scan

# ---------------------------------------------------------------------------
# Config edge branches
# ---------------------------------------------------------------------------


def _yml(tmp_path: Path, body: str) -> Path:
    f = tmp_path / ".scanipy.yml"
    f.write_text(textwrap.dedent(body))
    return f


def test_fail_on_null_is_none(tmp_path: Path) -> None:
    cfg = load_file_config(_yml(tmp_path, "fail_on: null\n"))
    assert cfg["fail_on"] is None


def test_fail_on_bad_value_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="fail_on"):
        load_file_config(_yml(tmp_path, "fail_on: nope\n"))


def test_detectors_non_string_entry_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="entries must be strings"):
        load_file_config(_yml(tmp_path, "detectors:\n  - 123\n"))


def test_severity_non_string_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="severity_threshold"):
        load_file_config(_yml(tmp_path, "severity_threshold: 5\n"))


def test_malformed_yaml_config_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="could not read config"):
        load_file_config(_yml(tmp_path, "key: [unterminated\n"))


def test_pyproject_tool_scanipy_not_a_table_raises(tmp_path: Path) -> None:
    if config_mod._tomllib is None:  # pragma: no cover - 3.10 only
        pytest.skip("tomllib unavailable on this interpreter")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool]\nscanipy = "not-a-table"\n')
    with pytest.raises(ConfigError, match=r"\[tool.scanipy\] must be a table"):
        load_file_config(pyproject)


def test_load_config_explicit_path(tmp_path: Path) -> None:
    cfg = load_config(_yml(tmp_path, "severity_threshold: high\n"))
    assert cfg.severity_threshold is Severity.HIGH


def test_load_config_discovers_from_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _yml(tmp_path, "output_format: json\n")
    monkeypatch.chdir(tmp_path)
    assert load_config().output_format == "json"


def test_load_config_no_file_returns_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_config() == ScanConfig()


# ---------------------------------------------------------------------------
# Scanner per-file isolation: analysis failure is captured, not fatal
# ---------------------------------------------------------------------------


def test_analysis_failure_is_captured_not_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")

    from scanipy.engine.taint import TaintEngine as RealEngine

    def _boom(self: Any, module: Any) -> list[Finding]:
        raise RuntimeError("synthetic engine crash")

    monkeypatch.setattr(RealEngine, "analyze", _boom)
    result = run_scan(tmp_path, [], ScannerScanConfig())
    # The crash was recorded as a parse error and the scan still returned cleanly.
    assert result.findings == ()
    assert any("analysis failed" in err.reason for err in result.parse_errors)


def test_parse_raising_is_captured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")

    def _raise(self: Any, path: Path) -> Any:
        raise OSError("synthetic read crash")

    monkeypatch.setattr(PythonFrontend, "parse", _raise)
    result = run_scan(tmp_path, [], ScannerScanConfig())
    assert any("parse failed" in err.reason for err in result.parse_errors)


# ---------------------------------------------------------------------------
# Taint binding through unpacking / attribute / subscript targets
# ---------------------------------------------------------------------------

_SPEC = DetectorSpec(
    id="test.detector",
    name="Test detector",
    cwe="CWE-000",
    severity=Severity.HIGH,
    languages=("python",),
    message="tainted value reaches a sink",
    sources=(Pattern(kind=PatternKind.CALL, pattern="input"),),
    sinks=(Pattern(kind=PatternKind.CALL, pattern="os.system", args=(0,)),),
)


def _analyze(tmp_path: Path, source: str) -> list[Finding]:
    file = tmp_path / "case.py"
    file.write_text(textwrap.dedent(source))
    module = PythonFrontend().parse(file)
    assert module is not None
    return TaintEngine([_SPEC]).analyze(module)


def test_tuple_unpacking_distributes_taint(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            a, b = input(), "safe"
            os.system(a)
        """,
    )
    assert len(findings) == 1


def test_star_unpacking_carries_taint(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            first, *rest = [input(), "x"]
            os.system(first)
        """,
    )
    assert len(findings) == 1


def test_attribute_target_binds_taint(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        class C:
            pass
        def f():
            c = C()
            c.value = input()
            os.system(c.value)
        """,
    )
    assert len(findings) == 1


def test_subscript_target_binds_taint(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            d = {}
            d["k"] = input()
            os.system(d["k"])
        """,
    )
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# python -m scanipy entry point
# ---------------------------------------------------------------------------


def test_main_module_entry_point_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    # Invoke `python -m scanipy --version` in-process (no subprocess) and confirm
    # the entry point wires through to the CLI, which exits 0 on --version.
    monkeypatch.setattr(sys, "argv", ["scanipy", "--version"])
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("scanipy", run_name="__main__")
    assert excinfo.value.code == 0
