# SPDX-License-Identifier: Apache-2.0
"""Intraprocedural taint TP/TN tests (ENGINE_11).

Each case parses a tiny Python source through the real
:class:`~scanipy.frontends.python_frontend.PythonFrontend` (so the IR is exactly
what the engine sees in production) and runs a crafted, single-spec
:class:`~scanipy.engine.taint.TaintEngine`. The specs here are *test data*, not the
bundled catalog (which WP-E owns), so the engine mechanics are exercised
independently of any particular detector.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from scanipy.dsl import DetectorSpec, Flow, Pattern, PatternKind, Propagator
from scanipy.engine.taint import TaintEngine
from scanipy.frontends.python_frontend import PythonFrontend
from scanipy.models import Finding, Severity, WitnessRole


def _spec(
    *,
    sources: tuple[Pattern, ...],
    sinks: tuple[Pattern, ...],
    sanitizers: tuple[Pattern, ...] = (),
    propagators: tuple[Propagator, ...] = (),
    spec_id: str = "test.detector",
    cwe: str = "CWE-000",
) -> DetectorSpec:
    return DetectorSpec(
        id=spec_id,
        name="Test detector",
        cwe=cwe,
        severity=Severity.HIGH,
        languages=("python",),
        message="test flow reaches a sink",
        sources=sources,
        sinks=sinks,
        sanitizers=sanitizers,
        propagators=propagators,
    )


# A reusable os-command-shaped spec: input() source, os.system arg0 sink, shlex.quote sanitizer.
OS_SPEC = _spec(
    sources=(Pattern(kind=PatternKind.CALL, pattern="input"),),
    sinks=(Pattern(kind=PatternKind.CALL, pattern="os.system", args=(0,)),),
    sanitizers=(Pattern(kind=PatternKind.CALL, pattern="shlex.quote"),),
    propagators=(
        Propagator(
            pattern=Pattern(kind=PatternKind.CALL, pattern="os.path.join"),
            flow=Flow(from_="any-arg", to="return"),
        ),
    ),
)


def _analyze(tmp_path: Path, source: str, spec: DetectorSpec = OS_SPEC) -> list[Finding]:
    file = tmp_path / "case.py"
    file.write_text(textwrap.dedent(source))
    module = PythonFrontend().parse(file)
    assert module is not None
    return TaintEngine([spec]).analyze(module)


# ---------------------------------------------------------------------------
# True positives
# ---------------------------------------------------------------------------


def test_direct_source_into_sink(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            os.system(input())
        """,
    )
    assert len(findings) == 1
    roles = [w.role for w in findings[0].witness]
    assert roles == [WitnessRole.SOURCE, WitnessRole.SINK]


def test_through_assignment(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            t = input()
            os.system(t)
        """,
    )
    assert len(findings) == 1


def test_through_string_concat(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            t = input()
            os.system("echo " + t)
        """,
    )
    assert len(findings) == 1


def test_through_fstring(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            t = input()
            os.system(f"echo {t}")
        """,
    )
    assert len(findings) == 1


def test_through_percent_format(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            t = input()
            os.system("echo %s" % t)
        """,
    )
    assert len(findings) == 1


def test_through_spec_propagator(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            t = input()
            cmd = os.path.join("/bin", t)
            os.system(cmd)
        """,
    )
    assert len(findings) == 1


def test_augmented_assignment_taints(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            cmd = "echo "
            cmd += input()
            os.system(cmd)
        """,
    )
    assert len(findings) == 1


def test_witness_exact_roles_and_lines(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            t = input()
            os.system("echo " + t)
        """,
    )
    assert len(findings) == 1
    witness = findings[0].witness
    assert [(w.role, w.location.line) for w in witness] == [
        (WitnessRole.SOURCE, 4),
        (WitnessRole.SINK, 5),
    ]
    assert findings[0].location.line == 5


# ---------------------------------------------------------------------------
# True negatives
# ---------------------------------------------------------------------------


def test_sanitizer_clears_taint(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        import shlex
        def f():
            t = input()
            os.system(shlex.quote(t))
        """,
    )
    assert findings == []


def test_reassignment_to_constant_kills_taint(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            t = input()
            t = "safe"
            os.system(t)
        """,
    )
    assert findings == []


def test_untainted_constant_not_flagged(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            os.system("ls -la")
        """,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# One-sided sanitizers (the load-bearing P5 rule)
# ---------------------------------------------------------------------------


def test_sanitized_on_one_branch_still_flagged(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        import shlex
        def f(flag):
            t = input()
            if flag:
                t = shlex.quote(t)
            os.system("echo " + t)
        """,
    )
    # Union-at-join: the else path is still tainted, so a finding is produced.
    assert len(findings) == 1


def test_sanitized_on_both_branches_not_flagged(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        import shlex
        def f(flag):
            t = input()
            if flag:
                t = shlex.quote(t)
            else:
                t = shlex.quote(t)
            os.system("echo " + t)
        """,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Sink argument / when-constraint restrictions
# ---------------------------------------------------------------------------


def test_sink_arg_restriction_respected(tmp_path: Path) -> None:
    # The spec restricts the sink to arg index 1; taint lands in arg 0 -> no finding.
    spec = _spec(
        sources=(Pattern(kind=PatternKind.CALL, pattern="input"),),
        sinks=(Pattern(kind=PatternKind.CALL, pattern="sink.fn", args=(1,)),),
    )
    findings = _analyze(
        tmp_path,
        """
        import sink
        def f():
            t = input()
            sink.fn(t, "constant")
        """,
        spec=spec,
    )
    assert findings == []


def test_when_shell_true_required(tmp_path: Path) -> None:
    spec = _spec(
        sources=(Pattern(kind=PatternKind.CALL, pattern="input"),),
        sinks=(
            Pattern(
                kind=PatternKind.CALL,
                pattern="subprocess.*",
                when={"keyword": {"shell": True}},
            ),
        ),
    )
    tainted_shell_true = _analyze(
        tmp_path,
        """
        import subprocess
        def f():
            t = input()
            subprocess.run(t, shell=True)
        """,
        spec=spec,
    )
    assert len(tainted_shell_true) == 1


def test_when_shell_false_not_flagged(tmp_path: Path) -> None:
    spec = _spec(
        sources=(Pattern(kind=PatternKind.CALL, pattern="input"),),
        sinks=(
            Pattern(
                kind=PatternKind.CALL,
                pattern="subprocess.*",
                when={"keyword": {"shell": True}},
            ),
        ),
    )
    findings = _analyze(
        tmp_path,
        """
        import subprocess
        def f():
            t = input()
            subprocess.run(["echo", t])
        """,
        spec=spec,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Access-path field sensitivity & loops
# ---------------------------------------------------------------------------


def test_attribute_path_tainted_and_sinked(tmp_path: Path) -> None:
    spec = _spec(
        sources=(Pattern(kind=PatternKind.ATTRIBUTE, pattern="flask.request.*"),),
        sinks=(Pattern(kind=PatternKind.CALL, pattern="os.system", args=(0,)),),
    )
    findings = _analyze(
        tmp_path,
        """
        import os
        import flask
        def f():
            data = flask.request.args
            os.system(data)
        """,
        spec=spec,
    )
    assert len(findings) == 1
    assert findings[0].witness[0].role is WitnessRole.SOURCE


def test_loop_reaches_fixpoint_and_flags(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f(items):
            cmd = ""
            for item in items:
                cmd = input()
            os.system(cmd)
        """,
    )
    # Tainted-in-loop reaches the sink via the back-edge join; terminates + flags.
    assert len(findings) == 1
