# SPDX-License-Identifier: Apache-2.0
"""End-to-end engine integration over the real fixtures (ENGINE_14).

Drives the full path that production uses — :func:`PythonFrontend.parse` +
:func:`load_builtin_detectors` + :meth:`TaintEngine.analyze` — over the existing
os-command true-positive / true-negative fixtures. SQL is exercised against a
hand-written ``tmp_path`` source because the sql fixtures are authored later by
WP-E; this suite does not author detector fixtures.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from scanipy.engine.taint import TaintEngine
from scanipy.frontends.python_frontend import PythonFrontend
from scanipy.models import WitnessRole
from scanipy.registry import load_builtin_detectors

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "python"


def _analyze_file(path: Path) -> list:
    module = PythonFrontend().parse(path)
    assert module is not None, f"frontend failed to parse {path}"
    return TaintEngine(load_builtin_detectors()).analyze(module)


def test_os_command_vulnerable_yields_one_cwe78_finding() -> None:
    findings = _analyze_file(FIXTURES / "vulnerable" / "os-command.py")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.cwe == "CWE-78"
    assert finding.detector_id == "python.injection.os-command"
    # Witness shape: input() source -> os.system sink.
    roles = [w.role for w in finding.witness]
    assert roles[0] is WitnessRole.SOURCE
    assert roles[-1] is WitnessRole.SINK
    assert finding.witness[0].location.line == 9  # input("name: ")
    assert finding.location.line == 10  # os.system(...)
    assert finding.fingerprint is not None and len(finding.fingerprint) == 64


def test_os_command_safe_yields_no_finding() -> None:
    findings = _analyze_file(FIXTURES / "safe" / "os-command.py")
    assert findings == []


def test_sql_concat_is_flagged(tmp_path: Path) -> None:
    file = tmp_path / "sql_vuln.py"
    file.write_text(
        textwrap.dedent(
            """
            def query(cursor):
                name = input()
                cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
            """
        )
    )
    module = PythonFrontend().parse(file)
    assert module is not None
    findings = TaintEngine(load_builtin_detectors()).analyze(module)
    sql = [f for f in findings if f.cwe == "CWE-89"]
    assert len(sql) == 1
    assert sql[0].detector_id == "python.injection.sql"


def test_sql_bound_parameters_not_flagged(tmp_path: Path) -> None:
    file = tmp_path / "sql_safe.py"
    file.write_text(
        textwrap.dedent(
            """
            def query(cursor):
                name = input()
                cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
            """
        )
    )
    module = PythonFrontend().parse(file)
    assert module is not None
    findings = TaintEngine(load_builtin_detectors()).analyze(module)
    assert [f for f in findings if f.cwe == "CWE-89"] == []


def test_from_import_alias_resolves_to_os_system(tmp_path: Path) -> None:
    # Import aliasing (resolved by the frontend) still matches the dotted pattern.
    file = tmp_path / "aliased.py"
    file.write_text(
        textwrap.dedent(
            """
            from os import system
            def f():
                t = input()
                system("echo " + t)
            """
        )
    )
    module = PythonFrontend().parse(file)
    assert module is not None
    findings = TaintEngine(load_builtin_detectors()).analyze(module)
    assert any(f.cwe == "CWE-78" for f in findings)


def test_repeated_analysis_is_deterministic() -> None:
    path = FIXTURES / "vulnerable" / "os-command.py"
    first = _analyze_file(path)
    second = _analyze_file(path)
    assert [f.to_dict() for f in first] == [f.to_dict() for f in second]
