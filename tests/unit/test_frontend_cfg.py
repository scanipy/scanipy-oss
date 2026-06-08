# SPDX-License-Identifier: Apache-2.0
"""Control-flow lowering tests via end-to-end taint flow (``python_frontend.py``).

The frontend builds a per-function CFG; the cleanest way to verify those edges
are correct is to drive a tainted value through each control construct and assert
the engine still reaches the sink (the union-at-join, back-edge, and handler edges
must all be present). Each case parses real source through the production frontend
and runs a single os-command-shaped crafted spec.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from scanipy.dsl import DetectorSpec, Pattern, PatternKind
from scanipy.engine.taint import TaintEngine
from scanipy.frontends.python_frontend import PythonFrontend
from scanipy.models import Finding, Severity

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
    assert module is not None, "frontend should parse this source"
    return TaintEngine([_SPEC]).analyze(module)


def test_taint_through_try_except_finally(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            t = input()
            try:
                pass
            except ValueError as exc:
                t = str(exc)
            finally:
                os.system(t)
        """,
    )
    assert len(findings) == 1


def test_taint_through_with_as(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            with open("x") as fh:
                t = input()
                os.system(t)
        """,
    )
    assert len(findings) == 1


def test_taint_through_for_else(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f(items):
            t = input()
            for _ in items:
                pass
            else:
                os.system(t)
        """,
    )
    assert len(findings) == 1


def test_taint_through_while_else(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            t = input()
            n = 0
            while n < 1:
                n += 1
            else:
                os.system(t)
        """,
    )
    assert len(findings) == 1


def test_taint_survives_break_in_loop(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f(items):
            t = input()
            for _ in items:
                if t:
                    break
                continue
            os.system(t)
        """,
    )
    assert len(findings) == 1


def test_taint_through_raise_in_branch(tmp_path: Path) -> None:
    # The raising branch ends without a successor; the other path still reaches.
    findings = _analyze(
        tmp_path,
        """
        import os
        def f(flag):
            t = input()
            if flag:
                raise RuntimeError("boom")
            os.system(t)
        """,
    )
    assert len(findings) == 1


def test_taint_in_async_function(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        async def handler():
            t = input()
            os.system(t)
        """,
    )
    assert len(findings) == 1


def test_taint_through_async_for_and_with(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        async def handler(stream, lock):
            t = input()
            async with lock:
                async for _ in stream:
                    pass
            os.system(t)
        """,
    )
    assert len(findings) == 1


def test_walrus_binding_in_expr_statement_carries_taint(tmp_path: Path) -> None:
    # A walrus inside an expression statement is surfaced as a binding, so the
    # captured name carries taint to a later sink. (A walrus inside an if/while
    # *test* is a documented v1 limitation and is not bound — see deviations.)
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            print(t := input())
            os.system(t)
        """,
    )
    assert len(findings) == 1


def test_annotated_assignment_without_value_binds_nothing(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            t: str
            t = input()
            os.system(t)
        """,
    )
    assert len(findings) == 1


def test_delete_and_global_statements_do_not_crash(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        _CONFIG = None
        def f():
            global _CONFIG
            t = input()
            tmp = t
            del tmp
            os.system(t)
        """,
    )
    assert len(findings) == 1


def test_reassign_in_except_does_not_kill_finally_path(tmp_path: Path) -> None:
    # Sanitizing only in the except branch must NOT clear taint on the try path
    # (union at the join — the load-bearing P5 rule, here via try/except edges).
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            t = input()
            try:
                pass
            except Exception:
                t = "safe"
            os.system(t)
        """,
    )
    assert len(findings) == 1
