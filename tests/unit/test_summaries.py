# SPDX-License-Identifier: Apache-2.0
"""Interprocedural TITO summary tests: splicing + recursion (ENGINE_12).

Drives the engine over multi-function modules (parsed by the real frontend) to
verify: a helper that forwards a parameter to a sink flags at the helper site with
a spliced ``source -> arg-enters-param -> sink`` witness; a wrapper that returns
its tainted parameter taints the caller's result; in-body callee sources reach
caller sinks; and self / mutual recursion terminates within the bounded fixpoint.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from scanipy.dsl import DetectorSpec, Pattern, PatternKind
from scanipy.engine.summaries import SUMMARY_FIXPOINT_CAP, compute_summaries
from scanipy.engine.taint import TaintEngine
from scanipy.frontends.python_frontend import PythonFrontend
from scanipy.models import Finding, Severity, WitnessRole

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


def _analyze(tmp_path: Path, source: str, spec: DetectorSpec = OS_SPEC) -> list[Finding]:
    file = tmp_path / "case.py"
    file.write_text(textwrap.dedent(source))
    module = PythonFrontend().parse(file)
    assert module is not None
    return TaintEngine([spec]).analyze(module)


def _module(tmp_path: Path, source: str) -> object:
    file = tmp_path / "case.py"
    file.write_text(textwrap.dedent(source))
    module = PythonFrontend().parse(file)
    assert module is not None
    return module


# ---------------------------------------------------------------------------
# Splicing
# ---------------------------------------------------------------------------


def test_param_to_sink_emits_at_helper_with_spliced_witness(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def helper(p):
            os.system(p)
        def caller():
            t = input()
            helper(t)
        """,
    )
    assert len(findings) == 1
    roles = [w.role for w in findings[0].witness]
    # source (caller) -> propagator (arg enters param at call) -> sink (in helper)
    assert roles == [WitnessRole.SOURCE, WitnessRole.PROPAGATOR, WitnessRole.SINK]
    assert findings[0].witness[0].location.line == 6  # input() in caller
    assert findings[0].witness[-1].location.line == 4  # os.system inside helper


def test_param_to_return_wrapper_taints_caller(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def wrap(p):
            return p + "!"
        def caller():
            t = input()
            y = wrap(t)
            os.system(y)
        """,
    )
    assert len(findings) == 1
    roles = [w.role for w in findings[0].witness]
    assert roles[0] is WitnessRole.SOURCE
    assert roles[-1] is WitnessRole.SINK


def test_in_body_source_and_sink_emitted_once_when_callee(tmp_path: Path) -> None:
    # ``leaf`` contains both its own source and its own sink (an intraprocedural
    # finding). Calling it from elsewhere must NOT re-report it at the call site
    # (which would carry a malformed PROPAGATOR-first witness).
    findings = _analyze(
        tmp_path,
        """
        import os
        def leaf():
            t = input()
            os.system(t)
        def caller():
            leaf()
        """,
    )
    assert len(findings) == 1
    assert [w.role for w in findings[0].witness] == [WitnessRole.SOURCE, WitnessRole.SINK]


def test_clean_param_not_propagated(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def wrap(p):
            return p + "!"
        def caller():
            y = wrap("constant")
            os.system(y)
        """,
    )
    assert findings == []


def test_in_body_source_reaches_caller_via_return(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def get_input():
            return input()
        def caller():
            y = get_input()
            os.system(y)
        """,
    )
    assert len(findings) == 1
    assert findings[0].witness[-1].role is WitnessRole.SINK


def test_self_flow_method_receiver(tmp_path: Path) -> None:
    spec = DetectorSpec(
        id="test.self",
        name="self",
        cwe="CWE-000",
        severity=Severity.HIGH,
        languages=("python",),
        message="receiver taint reaches sink",
        sources=(Pattern(kind=PatternKind.CALL, pattern="input"),),
        sinks=(Pattern(kind=PatternKind.CALL, pattern="os.system", args=(0,)),),
    )
    findings = _analyze(
        tmp_path,
        """
        import os
        class C:
            def run(self):
                os.system(self)
        def caller():
            obj = input()
            obj.run()
        """,
        spec=spec,
    )
    # A tainted receiver flowing into the method's in-body sink (the self-marker
    # summary applied at the ``obj.run()`` call site) is flagged with a spliced
    # source -> call -> sink witness.
    assert len(findings) == 1
    roles = [w.role for w in findings[0].witness]
    assert roles == [WitnessRole.SOURCE, WitnessRole.PROPAGATOR, WitnessRole.SINK]


# ---------------------------------------------------------------------------
# Recursion termination
# ---------------------------------------------------------------------------


def test_self_recursion_terminates(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def rec(p, n):
            if n > 0:
                return rec(p, n - 1)
            os.system(p)
            return p
        def caller():
            t = input()
            rec(t, 3)
        """,
    )
    assert len(findings) == 1


def test_mutual_recursion_terminates(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def a(p, n):
            if n > 0:
                return b(p, n - 1)
            os.system(p)
        def b(p, n):
            return a(p, n - 1)
        def caller():
            t = input()
            a(t, 3)
        """,
    )
    assert len(findings) == 1


def test_summary_fixpoint_cap_is_bounded() -> None:
    # A small, sane bound that guarantees termination on cyclic SCCs (P3 risk reg).
    assert 1 <= SUMMARY_FIXPOINT_CAP <= 32


# ---------------------------------------------------------------------------
# External-callee fallback
# ---------------------------------------------------------------------------


def test_external_callee_passes_taint_through(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        import third_party
        def f():
            t = input()
            wrapped = third_party.transform(t)
            os.system(wrapped)
        """,
    )
    # Unknown external callee: conservative pass-through (any-arg -> return).
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Summary computation surface
# ---------------------------------------------------------------------------


def test_compute_summaries_records_param_to_sink_flow(tmp_path: Path) -> None:
    module = _module(
        tmp_path,
        """
        import os
        def helper(p):
            os.system(p)
        """,
    )
    summaries = compute_summaries(module, [OS_SPEC])  # type: ignore[arg-type]
    helper = summaries["helper"]
    assert any(
        flow.src_kind == "param" and flow.dst_kind == "sink" and flow.spec_id == OS_SPEC.id
        for flow in helper.flows
    )


def test_summaries_are_deterministically_sorted(tmp_path: Path) -> None:
    module = _module(
        tmp_path,
        """
        import os
        def helper(p, q):
            os.system(p)
            os.system(q)
        """,
    )
    s1 = compute_summaries(module, [OS_SPEC])  # type: ignore[arg-type]
    s2 = compute_summaries(module, [OS_SPEC])  # type: ignore[arg-type]
    assert s1["helper"].flows == s2["helper"].flows
