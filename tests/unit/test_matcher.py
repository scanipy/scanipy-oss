# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the pattern matcher (:mod:`scanipy.engine.matcher`).

The matcher consumes the *real* IR node types from :mod:`scanipy.ir`. These
tests construct those real nodes via tiny local factories (mypy does not check
tests and there is no engine caller in this PR, so feeding real nodes is what
actually proves the matcher/IR seam — wrong field names would slip past ruff and
mypy otherwise).

Coverage maps to the WP-C "C green" acceptance bullets: the kind gate, the three
wildcard modes (exact / trailing-single / leading-greedy), ``None`` dotted names,
``args`` resolution (default / restriction / out-of-range / negatives /
sorted-deduped / receiver-excluded), ``when`` literal-equality (true / false /
absent / non-literal / multi-pair AND / unknown key), ``when``/``args`` ignored on
non-call kinds, and purity/determinism.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from scanipy.dsl.patterns import Pattern, PatternKind
from scanipy.engine.matcher import (
    MatchResult,
    _match_dotted,
    _resolve_arg_indices,
    match,
    matches,
)
from scanipy.ir import (
    ImportEntry,
    IRAttribute,
    IRCall,
    IRKeyword,
    IRLiteral,
    IRName,
    IRParam,
)
from scanipy.models import Location

pytestmark = pytest.mark.unit

LOC = Location(file="t.py", line=1, column=0)


# ---------------------------------------------------------------------------
# Real-IR node factories (the seam-proving inputs)
# ---------------------------------------------------------------------------


def _name(value: str) -> IRName:
    return IRName(name=value, canonical=value, location=LOC)


def _literal(value: object) -> IRLiteral:
    return IRLiteral(value=value, is_constant=True, location=LOC)


def _nonliteral() -> IRName:
    """A non-constant expression usable as a keyword value (e.g. a variable)."""
    return IRName(name="flag", canonical=None, location=LOC)


def _kw(name: str | None, value: object) -> IRKeyword:
    return IRKeyword(name=name, value=value, location=LOC)  # type: ignore[arg-type]


def _call(
    callee_path: str | None,
    *,
    args: tuple[object, ...] = (),
    kwargs: tuple[IRKeyword, ...] = (),
) -> IRCall:
    callee = _name(callee_path) if callee_path is not None else _name("anon")
    return IRCall(
        callee=callee,
        callee_path=callee_path,
        receiver=None,
        args=args,  # type: ignore[arg-type]
        kwargs=kwargs,
        location=LOC,
    )


def _attr(canonical: str | None) -> IRAttribute:
    return IRAttribute(value=_name("base"), attr="x", canonical=canonical, location=LOC)


def _import(canonical: str) -> ImportEntry:
    return ImportEntry(
        local_name=canonical.split(".")[-1],
        canonical=canonical,
        kind="name",
        asname=None,
        location=LOC,
    )


def _param(name: str) -> IRParam:
    return IRParam(name=name, index=0, kind="arg", location=LOC)


def _call_pat(pattern: str, **kw: object) -> Pattern:
    return Pattern(kind=PatternKind.CALL, pattern=pattern, **kw)  # type: ignore[arg-type]


def _attr_pat(pattern: str) -> Pattern:
    return Pattern(kind=PatternKind.ATTRIBUTE, pattern=pattern)


# ---------------------------------------------------------------------------
# Kind gate
# ---------------------------------------------------------------------------


def test_kind_gate_call_pattern_rejects_attribute_node() -> None:
    assert match(_call_pat("os.system"), _attr("os.system")) is None


def test_kind_gate_attribute_pattern_rejects_call_node() -> None:
    assert match(_attr_pat("flask.request.args"), _call("flask.request.args")) is None


def test_kind_gate_import_pattern_rejects_call_node() -> None:
    pat = Pattern(kind=PatternKind.IMPORT, pattern="pickle")
    assert match(pat, _call("pickle")) is None


def test_kind_gate_parameter_pattern_rejects_call_node() -> None:
    pat = Pattern(kind=PatternKind.PARAMETER, pattern="request")
    assert match(pat, _call("request")) is None


def test_call_pattern_matches_call_node() -> None:
    assert match(_call_pat("os.system"), _call("os.system")) is not None


# ---------------------------------------------------------------------------
# EXACT wildcard mode
# ---------------------------------------------------------------------------


def test_exact_match_dotted() -> None:
    result = match(_call_pat("os.system"), _call("os.system"))
    assert result == MatchResult(dotted_name="os.system", arg_indices=())


def test_exact_no_match_sibling() -> None:
    assert match(_call_pat("os.system"), _call("os.popen")) is None


def test_exact_bare_builtin_matches_only_bare() -> None:
    assert match(_call_pat("input"), _call("input")) is not None


def test_exact_bare_builtin_rejects_qualified() -> None:
    # bare `input` must NOT match a qualified mymod.input.
    assert match(_call_pat("input"), _call("mymod.input")) is None


# ---------------------------------------------------------------------------
# TRAILING-SINGLE wildcard mode (exactly one segment)
# ---------------------------------------------------------------------------


def test_trailing_single_positive() -> None:
    result = match(_call_pat("subprocess.*"), _call("subprocess.run"))
    assert result is not None
    assert result.dotted_name == "subprocess.run"


def test_trailing_single_rejects_too_deep() -> None:
    assert match(_call_pat("subprocess.*"), _call("subprocess.run.foo")) is None


def test_trailing_single_rejects_bare_prefix() -> None:
    assert match(_call_pat("subprocess.*"), _call("subprocess")) is None


def test_trailing_single_attribute_positive() -> None:
    assert match(_attr_pat("flask.request.*"), _attr("flask.request.args")) is not None


def test_trailing_single_attribute_rejects_deeper() -> None:
    assert match(_attr_pat("flask.request.*"), _attr("flask.request.args.get")) is None


# ---------------------------------------------------------------------------
# LEADING-GREEDY wildcard mode (one or more segments)
# ---------------------------------------------------------------------------


def test_leading_greedy_single_segment_receiver() -> None:
    assert match(_call_pat("*.execute"), _call("db.execute")) is not None


def test_leading_greedy_deep_receiver_orm_case() -> None:
    # The load-bearing idiomatic ORM/DBAPI case.
    result = match(_call_pat("*.execute"), _call("self.db.cursor.execute"))
    assert result is not None
    assert result.dotted_name == "self.db.cursor.execute"


def test_leading_greedy_specific_tail_positive() -> None:
    assert match(_call_pat("*.cursor.execute"), _call("self.db.cursor.execute")) is not None


def test_leading_greedy_specific_tail_negative() -> None:
    assert match(_call_pat("*.cursor.execute"), _call("self.db.execute")) is None


def test_leading_greedy_is_segment_wise_not_substring() -> None:
    # `*.execute` must NOT match `db.executemany` (segment-wise, not substring).
    assert match(_call_pat("*.execute"), _call("db.executemany")) is None


def test_leading_greedy_requires_at_least_one_prefix_segment() -> None:
    # '*' consumes one-or-more segments, so bare `execute` is not matched.
    assert match(_call_pat("*.execute"), _call("execute")) is None


# ---------------------------------------------------------------------------
# _match_dotted direct unit coverage (incl. defensive malformed inputs)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "name", "expected"),
    [
        ("os.system", "os.system", True),
        ("os.system", "os.popen", False),
        ("input", "input", True),
        ("input", "mymod.input", False),
        ("subprocess.*", "subprocess.run", True),
        ("subprocess.*", "subprocess.run.foo", False),
        ("subprocess.*", "subprocess", False),
        ("flask.request.*", "flask.request.args", True),
        ("flask.request.*", "flask.request.args.get", False),
        ("*.execute", "db.execute", True),
        ("*.execute", "self.db.cursor.execute", True),
        ("*.execute", "executemany", False),
        ("*.execute", "execute", False),
        ("*.cursor.execute", "self.db.cursor.execute", True),
        ("*.cursor.execute", "self.db.execute", False),
        ("*", "request", True),  # lone '*' = one segment
        ("*", "a.b", False),  # lone '*' consumes exactly one segment
    ],
)
def test_match_dotted_table(pattern: str, name: str, expected: bool) -> None:
    assert _match_dotted(pattern, name) is expected


@pytest.mark.parametrize(
    ("pattern", "name"),
    [
        ("", "os.system"),  # empty pattern never matches
        ("a.*.c", "a.b.c"),  # mid-segment wildcard unsupported
        ("*.*", "a.b"),  # multiple wildcards unsupported
        ("os.*.system", "os.x.system"),  # mid wildcard unsupported
    ],
)
def test_match_dotted_malformed_returns_false(pattern: str, name: str) -> None:
    # The parser now rejects these wildcard placements at load time (see
    # test_dsl_parser.test_wildcard_placement_rejected), so they cannot arrive via
    # parse_spec. Calling _match_dotted directly here exercises the matcher's
    # defense-in-depth no-widen behavior: were such a Pattern ever constructed
    # directly, the matcher must still never raise and never widen.
    assert _match_dotted(pattern, name) is False


# ---------------------------------------------------------------------------
# None / unresolved dotted name => None, never raises
# ---------------------------------------------------------------------------


def test_call_unresolved_name_returns_none() -> None:
    assert match(_call_pat("os.system"), _call(None)) is None


def test_attribute_unresolved_name_returns_none() -> None:
    assert match(_attr_pat("flask.request.args"), _attr(None)) is None


def test_unresolved_name_does_not_raise() -> None:
    # Even a wildcard pattern against a None name is a quiet no-match.
    assert match(_call_pat("*.execute"), _call(None)) is None


# ---------------------------------------------------------------------------
# args resolution
# ---------------------------------------------------------------------------


def test_args_none_yields_all_written_indices() -> None:
    node = _call("f", args=(_name("a"), _name("b"), _name("c")))
    result = match(_call_pat("f"), node)
    assert result is not None
    assert result.arg_indices == (0, 1, 2)


def test_args_none_on_zero_arg_call_is_empty_tuple() -> None:
    result = match(_call_pat("f"), _call("f"))
    assert result is not None
    assert result.arg_indices == ()


def test_args_restrict_in_range() -> None:
    node = _call("f", args=(_name("a"), _name("b")))
    result = match(_call_pat("f", args=(0,)), node)
    assert result is not None
    assert result.arg_indices == (0,)


def test_args_sorted_and_deduped() -> None:
    node = _call("f", args=(_name("a"), _name("b"), _name("c")))
    result = match(_call_pat("f", args=(2, 0, 0, 1)), node)
    assert result is not None
    assert result.arg_indices == (0, 1, 2)


def test_args_out_of_range_only_is_no_match() -> None:
    node = _call("f", args=(_name("a"), _name("b")))
    assert match(_call_pat("f", args=(5,)), node) is None


def test_args_negative_indices_dropped() -> None:
    node = _call("f", args=(_name("a"), _name("b")))
    result = match(_call_pat("f", args=(-1, 0)), node)
    assert result is not None
    assert result.arg_indices == (0,)


def test_args_all_negative_is_no_match() -> None:
    node = _call("f", args=(_name("a"),))
    assert match(_call_pat("f", args=(-1, -2)), node) is None


def test_args_receiver_excluded() -> None:
    # `*.execute` args=(0,) on a method call with one written arg targets the
    # first WRITTEN argument (the SQL string), not the receiver.
    node = _call("conn.cursor.execute", args=(_name("sql"),))
    result = match(_call_pat("*.execute", args=(0,)), node)
    assert result is not None
    assert result.arg_indices == (0,)


# ---------------------------------------------------------------------------
# when (keyword literal-equality)
# ---------------------------------------------------------------------------


def _shell_true() -> Mapping[str, object]:
    return {"keyword": {"shell": True}}


def test_when_shell_true_literal_matches() -> None:
    node = _call("subprocess.run", kwargs=(_kw("shell", _literal(True)),))
    result = match(_call_pat("subprocess.*", when=_shell_true()), node)
    assert result is not None
    assert result.dotted_name == "subprocess.run"


def test_when_shell_false_literal_no_match() -> None:
    node = _call("subprocess.run", kwargs=(_kw("shell", _literal(False)),))
    assert match(_call_pat("subprocess.*", when=_shell_true()), node) is None


def test_when_shell_absent_no_match() -> None:
    node = _call("subprocess.run", kwargs=())
    assert match(_call_pat("subprocess.*", when=_shell_true()), node) is None


def test_when_shell_non_literal_no_match() -> None:
    node = _call("subprocess.run", kwargs=(_kw("shell", _nonliteral()),))
    assert match(_call_pat("subprocess.*", when=_shell_true()), node) is None


def test_when_double_star_splat_kw_ignored() -> None:
    # A **kwargs splat (name=None) carries no usable literal and never satisfies.
    node = _call("subprocess.run", kwargs=(_kw(None, _name("opts")),))
    assert match(_call_pat("subprocess.*", when=_shell_true()), node) is None


def test_when_multiple_pairs_anded_all_satisfied() -> None:
    node = _call(
        "f",
        kwargs=(_kw("shell", _literal(True)), _kw("check", _literal(True))),
    )
    when: Mapping[str, object] = {"keyword": {"shell": True, "check": True}}
    assert match(_call_pat("f", when=when), node) is not None


def test_when_multiple_pairs_anded_one_missing_no_match() -> None:
    node = _call("f", kwargs=(_kw("shell", _literal(True)),))
    when: Mapping[str, object] = {"keyword": {"shell": True, "check": True}}
    assert match(_call_pat("f", when=when), node) is None


def test_when_unknown_top_key_never_widens() -> None:
    # An unsupported `when` condition must return no match (never widen).
    node = _call("f", kwargs=(_kw("shell", _literal(True)),))
    when: Mapping[str, object] = {"argument": {"x": 1}}
    assert match(_call_pat("f", when=when), node) is None


def test_when_keyword_value_must_be_mapping() -> None:
    node = _call("f", kwargs=(_kw("shell", _literal(True)),))
    when: Mapping[str, object] = {"keyword": "not-a-mapping"}
    assert match(_call_pat("f", when=when), node) is None


def test_when_ignored_when_none() -> None:
    # No `when` constraint -> only name/args gate.
    node = _call("subprocess.run", args=(_name("cmd"),))
    assert match(_call_pat("subprocess.*"), node) is not None


# ---------------------------------------------------------------------------
# when/args ignored on non-call kinds
# ---------------------------------------------------------------------------


def test_attribute_kind_ignores_args_and_when() -> None:
    # A constructed attribute pattern can technically carry args/when (the parser
    # rejects this, but the matcher must IGNORE it on non-call kinds, not crash).
    pat = Pattern(
        kind=PatternKind.ATTRIBUTE,
        pattern="flask.request.*",
        args=(0,),
        when={"keyword": {"x": True}},
    )
    result = match(pat, _attr("flask.request.args"))
    assert result == MatchResult(dotted_name="flask.request.args", arg_indices=())


def test_import_kind_match_and_empty_args() -> None:
    pat = Pattern(kind=PatternKind.IMPORT, pattern="flask.*")
    result = match(pat, _import("flask.request"))
    assert result == MatchResult(dotted_name="flask.request", arg_indices=())


def test_import_kind_exact() -> None:
    pat = Pattern(kind=PatternKind.IMPORT, pattern="pickle")
    assert match(pat, _import("pickle")) is not None
    assert match(pat, _import("json")) is None


def test_parameter_kind_matches_bare_name() -> None:
    pat = Pattern(kind=PatternKind.PARAMETER, pattern="request")
    result = match(pat, _param("request"))
    assert result == MatchResult(dotted_name="request", arg_indices=())


def test_parameter_kind_wildcard() -> None:
    pat = Pattern(kind=PatternKind.PARAMETER, pattern="*")
    # A lone '*' is a trailing-single wildcard consuming exactly one segment, so
    # it matches any bare single-segment name but not a dotted one.
    assert match(pat, _param("request")) is not None


# ---------------------------------------------------------------------------
# _resolve_arg_indices direct unit coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spec_args", "arg_count", "expected"),
    [
        (None, 0, ()),
        (None, 3, (0, 1, 2)),
        ((0,), 2, (0,)),
        ((1, 0), 2, (0, 1)),
        ((0, 0, 1), 2, (0, 1)),
        ((5,), 2, ()),
        ((-1, 0), 2, (0,)),
        ((-1,), 2, ()),
    ],
)
def test_resolve_arg_indices(
    spec_args: tuple[int, ...] | None, arg_count: int, expected: tuple[int, ...]
) -> None:
    assert _resolve_arg_indices(spec_args, arg_count) == expected


# ---------------------------------------------------------------------------
# matches() wrapper + purity / determinism (P3)
# ---------------------------------------------------------------------------


def test_matches_wrapper_true() -> None:
    assert matches(_call_pat("os.system"), _call("os.system")) is True


def test_matches_wrapper_false() -> None:
    assert matches(_call_pat("os.system"), _call("os.popen")) is False


def test_determinism_identical_inputs_equal_results() -> None:
    pat_a = _call_pat("subprocess.*", args=(2, 0, 1), when=_shell_true())
    pat_b = _call_pat("subprocess.*", args=(2, 0, 1), when=_shell_true())
    node_a = _call(
        "subprocess.run",
        args=(_name("x"), _name("y"), _name("z")),
        kwargs=(_kw("shell", _literal(True)),),
    )
    node_b = _call(
        "subprocess.run",
        args=(_name("x"), _name("y"), _name("z")),
        kwargs=(_kw("shell", _literal(True)),),
    )
    result_a = match(pat_a, node_a)
    result_b = match(pat_b, node_b)
    assert result_a == result_b
    assert result_a is not None
    # arg_indices is sorted even though the spec listed them out of order.
    assert result_a.arg_indices == (0, 1, 2)


def test_repeated_calls_are_stable() -> None:
    pat = _call_pat("*.execute", args=(0,))
    node = _call("self.db.cursor.execute", args=(_name("sql"),))
    first = match(pat, node)
    second = match(pat, node)
    assert first == second
