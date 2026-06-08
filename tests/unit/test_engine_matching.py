# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the engine's matcher glue and access-path derivation (ENGINE_10).

These exercise the engine's *use* of :func:`scanipy.engine.matcher.match` over
hand-built IR nodes (the matcher itself is tested in ``test_matcher.py``) plus the
access-path lattice helpers the dataflow depends on. No frontend dependency.
"""

from __future__ import annotations

from scanipy.dsl import Pattern, PatternKind
from scanipy.engine.matcher import match
from scanipy.engine.propagation import access_path_of
from scanipy.engine.taint_state import (
    STEPS_CAP,
    AccessPath,
    AccessStep,
)
from scanipy.ir import (
    IRAttribute,
    IRCall,
    IRKeyword,
    IRLiteral,
    IRName,
    IRSubscript,
)
from scanipy.models import Location

LOC = Location(file="t.py", line=1, column=0)


def _name(name: str, canonical: str | None = None) -> IRName:
    return IRName(name=name, canonical=canonical, location=LOC)


def _call(
    callee_path: str, args: tuple[object, ...] = (), kwargs: tuple[IRKeyword, ...] = ()
) -> IRCall:
    return IRCall(
        callee=_name(callee_path.split(".")[0]),
        callee_path=callee_path,
        receiver=None,
        args=tuple(a for a in args),  # type: ignore[arg-type]
        kwargs=kwargs,
        location=LOC,
    )


# ---------------------------------------------------------------------------
# Matcher glue over IR nodes
# ---------------------------------------------------------------------------


def test_call_pattern_matches_exact_callee_path() -> None:
    call = _call("os.system", args=(_name("x"),))
    result = match(Pattern(kind=PatternKind.CALL, pattern="os.system", args=(0,)), call)
    assert result is not None
    assert result.dotted_name == "os.system"
    assert result.arg_indices == (0,)


def test_call_pattern_leading_wildcard_matches_method_chain() -> None:
    call = _call("conn.cursor.execute", args=(_name("sql"),))
    assert match(Pattern(kind=PatternKind.CALL, pattern="*.execute", args=(0,)), call) is not None
    assert match(Pattern(kind=PatternKind.CALL, pattern="*.cursor.execute"), call) is not None


def test_call_pattern_arg_restriction_out_of_range_is_no_match() -> None:
    call = _call("os.system", args=(_name("x"),))
    assert match(Pattern(kind=PatternKind.CALL, pattern="os.system", args=(5,)), call) is None


def test_when_keyword_requires_literal_true() -> None:
    shell_true = IRKeyword(
        name="shell", value=IRLiteral(value=True, is_constant=True, location=LOC), location=LOC
    )
    shell_var = IRKeyword(name="shell", value=_name("flag"), location=LOC)
    pattern = Pattern(
        kind=PatternKind.CALL, pattern="subprocess.*", when={"keyword": {"shell": True}}
    )
    assert (
        match(pattern, _call("subprocess.run", args=(_name("c"),), kwargs=(shell_true,)))
        is not None
    )
    assert match(pattern, _call("subprocess.run", args=(_name("c"),), kwargs=(shell_var,))) is None
    assert match(pattern, _call("subprocess.run", args=(_name("c"),))) is None


def test_attribute_pattern_matches_resolved_chain() -> None:
    attr = IRAttribute(
        value=_name("request"), attr="args", canonical="flask.request.args", location=LOC
    )
    assert match(Pattern(kind=PatternKind.ATTRIBUTE, pattern="flask.request.*"), attr) is not None


def test_unresolved_callee_never_matches() -> None:
    unresolved = IRCall(
        callee=_name("f"), callee_path=None, receiver=None, args=(), kwargs=(), location=LOC
    )
    assert match(Pattern(kind=PatternKind.CALL, pattern="os.system"), unresolved) is None


# ---------------------------------------------------------------------------
# Access-path derivation
# ---------------------------------------------------------------------------


def test_access_path_of_name() -> None:
    assert access_path_of(_name("x")) == AccessPath(base="x")


def test_access_path_of_attribute_chain() -> None:
    expr = IRAttribute(value=_name("x"), attr="a", canonical=None, location=LOC)
    assert access_path_of(expr) == AccessPath(base="x", steps=(AccessStep("attr", "a"),))


def test_access_path_const_subscript_tracked() -> None:
    expr = IRSubscript(
        value=_name("d"),
        index=IRLiteral(value="k", is_constant=True, location=LOC),
        is_const_index=True,
        const_index="k",
        location=LOC,
    )
    assert access_path_of(expr) == AccessPath(base="d", steps=(AccessStep("index", repr("k")),))


def test_access_path_dynamic_subscript_collapses_to_base() -> None:
    expr = IRSubscript(
        value=_name("d"),
        index=_name("i"),
        is_const_index=False,
        const_index=None,
        location=LOC,
    )
    assert access_path_of(expr) == AccessPath(base="d")


def test_access_path_depth_cap_over_approximates() -> None:
    # x.a.b.c collapses to the STEPS_CAP prefix (over-approximation, P5-safe).
    deep = IRAttribute(
        value=IRAttribute(
            value=IRAttribute(value=_name("x"), attr="a", canonical=None, location=LOC),
            attr="b",
            canonical=None,
            location=LOC,
        ),
        attr="c",
        canonical=None,
        location=LOC,
    )
    ap = access_path_of(deep)
    assert ap is not None
    assert len(ap.steps) == STEPS_CAP
    assert ap == AccessPath(base="x", steps=(AccessStep("attr", "a"), AccessStep("attr", "b")))
