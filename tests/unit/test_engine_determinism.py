# SPDX-License-Identifier: Apache-2.0
"""Determinism and fingerprint tests (ENGINE_13, principle P3).

Verifies byte-identical findings across repeated runs and shuffled spec order, a
total order even when several findings share a sink (witness-fingerprint
tie-break), shortest-witness selection, and a stable golden fingerprint string
(guards against accidental fingerprint-format changes).
"""

from __future__ import annotations

import random
import textwrap
from pathlib import Path

from scanipy.dsl import DetectorSpec, Pattern, PatternKind
from scanipy.engine.taint import TaintEngine
from scanipy.engine.witness import (
    better_chain,
    finding_fingerprint,
    witness_fingerprint,
)
from scanipy.frontends.python_frontend import PythonFrontend
from scanipy.models import Finding, Location, Severity, WitnessRole, WitnessStep

OS_SPEC = DetectorSpec(
    id="test.os",
    name="os",
    cwe="CWE-078",
    severity=Severity.HIGH,
    languages=("python",),
    message="tainted value reaches os.system",
    sources=(Pattern(kind=PatternKind.CALL, pattern="input"),),
    sinks=(Pattern(kind=PatternKind.CALL, pattern="os.system", args=(0,)),),
)
SQL_SPEC = DetectorSpec(
    id="test.sql",
    name="sql",
    cwe="CWE-089",
    severity=Severity.HIGH,
    languages=("python",),
    message="tainted value reaches execute",
    sources=(Pattern(kind=PatternKind.CALL, pattern="input"),),
    sinks=(Pattern(kind=PatternKind.CALL, pattern="*.execute", args=(0,)),),
)


def _module(tmp_path: Path, source: str) -> object:
    file = tmp_path / "case.py"
    file.write_text(textwrap.dedent(source))
    module = PythonFrontend().parse(file)
    assert module is not None
    return module


def _fps(findings: list[Finding]) -> list[str | None]:
    return [f.fingerprint for f in findings]


def test_repeated_runs_are_byte_identical(tmp_path: Path) -> None:
    module = _module(
        tmp_path,
        """
        import os
        def f():
            t = input()
            os.system(t)
        """,
    )
    a = TaintEngine([OS_SPEC]).analyze(module)
    b = TaintEngine([OS_SPEC]).analyze(module)
    assert _fps(a) == _fps(b)
    assert [f.to_dict() for f in a] == [f.to_dict() for f in b]


def test_spec_order_does_not_change_output(tmp_path: Path) -> None:
    module = _module(
        tmp_path,
        """
        import os
        def f(cursor):
            t = input()
            os.system(t)
            cursor.execute(t)
        """,
    )
    base = TaintEngine([OS_SPEC, SQL_SPEC]).analyze(module)
    for seed in range(5):
        specs = [OS_SPEC, SQL_SPEC]
        random.Random(seed).shuffle(specs)
        assert _fps(TaintEngine(specs).analyze(module)) == _fps(base)


def test_total_order_with_multiple_findings(tmp_path: Path) -> None:
    module = _module(
        tmp_path,
        """
        import os
        def f():
            a = input()
            os.system(a)
            os.system(a)
        """,
    )
    findings = TaintEngine([OS_SPEC]).analyze(module)
    assert len(findings) == 2
    # Sorted by (file, line, column, ..., detector_id, fingerprint) -> ascending lines.
    lines = [f.location.line for f in findings]
    assert lines == sorted(lines)
    # The order is reproducible.
    again = TaintEngine([OS_SPEC]).analyze(module)
    assert _fps(findings) == _fps(again)


def test_fingerprint_is_field_derived_not_object_identity() -> None:
    loc = Location(file="t.py", line=10, column=4, end_line=10, end_column=20)
    source = WitnessStep(WitnessRole.SOURCE, Location("t.py", 9, 8), "source input")
    sink = WitnessStep(WitnessRole.SINK, loc, "sink os.system")
    fp1 = finding_fingerprint("test.os", "CWE-078", loc, (source, sink))
    fp2 = finding_fingerprint("test.os", "CWE-078", loc, (source, sink))
    assert fp1 == fp2
    assert len(fp1) == 64  # sha256 hex
    # A different witness yields a different fingerprint.
    other = finding_fingerprint("test.os", "CWE-078", loc, (sink,))
    assert other != fp1


def test_witness_fingerprint_golden() -> None:
    steps = (
        WitnessStep(WitnessRole.SOURCE, Location("t.py", 1, 0, 1, 5), ""),
        WitnessStep(WitnessRole.SINK, Location("t.py", 2, 0, 2, 9), ""),
    )
    # Golden value: guards the fingerprint string format against silent drift (P3).
    assert witness_fingerprint(steps) == (
        "a0bcccb5ee8f782682d4a9bae45bae330e466cd3d9c16b80115d7ec5e07c89c1"
    )


def test_os_command_fixture_golden_fingerprint() -> None:
    from scanipy.registry import load_builtin_detectors

    module = PythonFrontend().parse(Path("tests/fixtures/python/vulnerable/os-command.py"))
    assert module is not None
    findings = TaintEngine(load_builtin_detectors()).analyze(module)
    assert len(findings) == 1
    # Golden fingerprint over the os-command vulnerable fixture (P3 drift guard).
    assert findings[0].fingerprint == (
        "fd4ede02b2a3282dcecd43189fab1382de3f5252d6995412319b535a9d5a0719"
    )


def test_better_chain_prefers_shorter() -> None:
    short = (
        WitnessStep(WitnessRole.SOURCE, Location("t.py", 1, 0), ""),
        WitnessStep(WitnessRole.SINK, Location("t.py", 3, 0), ""),
    )
    long = (
        WitnessStep(WitnessRole.SOURCE, Location("t.py", 1, 0), ""),
        WitnessStep(WitnessRole.PROPAGATOR, Location("t.py", 2, 0), ""),
        WitnessStep(WitnessRole.SINK, Location("t.py", 3, 0), ""),
    )
    assert better_chain(long, short) is short
    assert better_chain(short, long) is short


def test_better_chain_lexicographic_tiebreak() -> None:
    a = (WitnessStep(WitnessRole.SOURCE, Location("t.py", 1, 0), ""),)
    b = (WitnessStep(WitnessRole.SOURCE, Location("t.py", 2, 0), ""),)
    assert better_chain(b, a) is a  # smaller location wins
