# SPDX-License-Identifier: Apache-2.0
"""Generic-propagation transfer tests (``propagation.py``).

The intraprocedural suite covers assignment, ``+``/``%``, f-strings, and spec
propagators. This module fills in the remaining *generic* propagation forms that
apply to every detector equally: boolean ops, conditional expressions, container
builds (lists / dict keys & values), comprehensions, starred spreads, and dynamic
subscripts. Each case runs a real source string through the frontend + engine
with a single os-command-shaped crafted spec (test data, not the catalog).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

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
    assert module is not None
    return TaintEngine([_SPEC]).analyze(module)


def test_boolop_or_propagates(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f(fallback):
            t = input()
            value = t or fallback
            os.system(value)
        """,
    )
    assert len(findings) == 1


def test_boolop_and_propagates(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f(flag):
            t = input()
            value = flag and t
            os.system(value)
        """,
    )
    assert len(findings) == 1


def test_ifexp_taints_when_either_arm_tainted(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f(flag, safe):
            t = input()
            value = t if flag else safe
            os.system(value)
        """,
    )
    assert len(findings) == 1


def test_dynamic_subscript_taints_container(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f(i):
            data = [input()]
            os.system(data[i])
        """,
    )
    # A dynamic index over-approximates to the tainted container (FP-biased).
    assert len(findings) == 1


def test_dict_value_taint_via_dynamic_key(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f(k):
            d = {"a": input()}
            os.system(d[k])
        """,
    )
    assert len(findings) == 1


def test_comprehension_taints_result(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f(items):
            t = input()
            joined = " ".join([t for _ in items])
            os.system(joined)
        """,
    )
    assert len(findings) == 1


def test_starred_spread_in_container_taints(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            parts = [input()]
            combined = " ".join([*parts])
            os.system(combined)
        """,
    )
    assert len(findings) == 1


def test_constant_subscript_is_field_sensitive(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            data = [input()]
            os.system(data[0])
        """,
    )
    assert len(findings) == 1


def test_clean_dict_key_lookup_not_flagged(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        """
        import os
        def f():
            d = {"a": "safe"}
            os.system(d["a"])
        """,
    )
    assert findings == []


@pytest.mark.parametrize("op", ["or", "and"])
def test_boolop_clean_not_flagged(tmp_path: Path, op: str) -> None:
    findings = _analyze(
        tmp_path,
        f"""
        import os
        def f():
            value = "x" {op} "y"
            os.system(value)
        """,
    )
    assert findings == []
