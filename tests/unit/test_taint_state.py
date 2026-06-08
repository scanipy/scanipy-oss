# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the access-path taint lattice (``taint_state.py``).

These exercise the lattice operations directly — prefix/extend (with the depth
cap and over-approximation), assign (kill-then-seed), seed (union-add), kill,
one-sided sanitize, union join, and the deterministic iteration order — as pure
value behavior, independent of the full engine.
"""

from __future__ import annotations

import pytest

from scanipy.engine.taint_state import (
    STEPS_CAP,
    AccessPath,
    AccessStep,
    TaintLabel,
    TaintProvenance,
    empty_env,
    with_replaced_chain,
)
from scanipy.models import Location, WitnessRole, WitnessStep


def _label(spec_id: str, *, line: int = 1) -> TaintLabel:
    step = WitnessStep(WitnessRole.SOURCE, Location("f.py", line, 0))
    return TaintLabel(spec_id=spec_id, provenance=TaintProvenance(spec_id, (step,)))


def _ap(base: str, *attrs: str) -> AccessPath:
    return AccessPath(base, tuple(AccessStep("attr", a) for a in attrs))


# ---------------------------------------------------------------------------
# AccessPath
# ---------------------------------------------------------------------------


def test_prefix_clamps_negative_to_zero() -> None:
    ap = _ap("x", "a", "b")
    assert ap.prefix(-3) == AccessPath("x", ())


def test_prefix_truncates() -> None:
    ap = _ap("x", "a", "b")
    assert ap.prefix(1) == _ap("x", "a")


def test_is_prefix_of_rules() -> None:
    assert _ap("x").is_prefix_of(_ap("x", "a"))
    assert _ap("x", "a").is_prefix_of(_ap("x", "a", "b"))
    assert not _ap("y").is_prefix_of(_ap("x", "a"))
    assert not _ap("x", "a", "b").is_prefix_of(_ap("x", "a"))
    assert not _ap("x", "z").is_prefix_of(_ap("x", "a"))


def test_extend_collapses_at_cap() -> None:
    ap = AccessPath("x")
    for name in ("a", "b", "c", "d"):
        ap = ap.extend(AccessStep("attr", name))
    # At the cap the path stays collapsed (over-approximation, P5-safe).
    assert len(ap.steps) == STEPS_CAP


def test_sort_key_includes_steps() -> None:
    assert _ap("x", "a").sort_key() == ("x", (("attr", "a"),))
    assert AccessPath("x").sort_key() == ("x", ())


# ---------------------------------------------------------------------------
# TaintEnv operations
# ---------------------------------------------------------------------------


def test_empty_env_is_empty() -> None:
    assert empty_env().is_empty()


def test_assign_then_get() -> None:
    env = empty_env().assign(_ap("x"), frozenset({_label("d")}))
    assert {label.spec_id for label in env.get(_ap("x"))} == {"d"}
    assert not env.is_empty()


def test_assign_empty_labels_leaves_path_clean() -> None:
    seeded = empty_env().assign(_ap("x"), frozenset({_label("d")}))
    cleaned = seeded.assign(_ap("x"), frozenset())
    assert cleaned.get(_ap("x")) == frozenset()
    assert cleaned.is_empty()


def test_assign_kills_extensions() -> None:
    env = empty_env().assign(_ap("x", "a"), frozenset({_label("d")}))
    # Rebinding the base clears the prior x.a taint (kill-then-seed).
    env = env.assign(_ap("x"), frozenset())
    assert env.get(_ap("x", "a")) == frozenset()


def test_seed_unions_without_killing() -> None:
    env = empty_env().assign(_ap("x"), frozenset({_label("d1")}))
    env = env.seed(_ap("x"), frozenset({_label("d2")}))
    assert {label.spec_id for label in env.get(_ap("x"))} == {"d1", "d2"}


def test_seed_empty_is_noop() -> None:
    env = empty_env().assign(_ap("x"), frozenset({_label("d")}))
    assert env.seed(_ap("x"), frozenset()) == env


def test_kill_removes_path_and_extensions() -> None:
    env = empty_env().assign(_ap("x", "a"), frozenset({_label("d")}))
    env = env.kill(_ap("x"))
    assert env.is_empty()


def test_get_over_approximates_up_the_prefix() -> None:
    # A label on the prefix x.a flows to a deeper read x.a.b (FP-biased, P5-safe).
    env = empty_env().assign(_ap("x", "a"), frozenset({_label("d")}))
    assert {label.spec_id for label in env.get(_ap("x", "a", "b"))} == {"d"}


def test_sanitize_is_one_sided_per_spec_and_path() -> None:
    env = empty_env().assign(_ap("x"), frozenset({_label("d1"), _label("d2")}))
    env = env.assign(_ap("y"), frozenset({_label("d1")}))
    sanitized = env.sanitize(_ap("x"), "d1")
    # d1 removed only on x; d2 on x and d1 on y are untouched.
    assert {label.spec_id for label in sanitized.get(_ap("x"))} == {"d2"}
    assert {label.spec_id for label in sanitized.get(_ap("y"))} == {"d1"}


def test_sanitize_removes_only_target_extensions() -> None:
    env = empty_env().assign(_ap("x", "a"), frozenset({_label("d")}))
    sanitized = env.sanitize(_ap("x"), "d")
    assert sanitized.get(_ap("x", "a")) == frozenset()


def test_join_unions_never_intersects() -> None:
    left = empty_env().assign(_ap("x"), frozenset({_label("d")}))
    right = empty_env()  # sanitized on this branch (x clean)
    joined = left.join(right)
    # Tainted on only one branch => still tainted at the join (the P5 rule).
    assert {label.spec_id for label in joined.get(_ap("x"))} == {"d"}


def test_join_merges_best_provenance_per_spec() -> None:
    short = _label("d", line=1)
    long_chain = (
        WitnessStep(WitnessRole.SOURCE, Location("f.py", 1, 0)),
        WitnessStep(WitnessRole.PROPAGATOR, Location("f.py", 2, 0)),
    )
    longer = TaintLabel("d", TaintProvenance("d", long_chain))
    left = empty_env().assign(_ap("x"), frozenset({short}))
    right = empty_env().assign(_ap("x"), frozenset({longer}))
    joined = left.join(right)
    labels = joined.get(_ap("x"))
    assert len(labels) == 1
    # The shorter witness chain wins (deterministic selection).
    assert len(next(iter(labels)).provenance.chain) == 1


def test_items_sorted_by_path() -> None:
    env = empty_env()
    env = env.assign(_ap("b"), frozenset({_label("d")}))
    env = env.assign(_ap("a"), frozenset({_label("d")}))
    bases = [ap.base for ap, _ in env.items()]
    assert bases == ["a", "b"]


def test_eq_returns_notimplemented_for_other_types() -> None:
    assert empty_env().__eq__("not an env") is NotImplemented


def test_with_replaced_chain_swaps_provenance() -> None:
    label = _label("d")
    new_chain = (WitnessStep(WitnessRole.SINK, Location("g.py", 9, 0)),)
    replaced = with_replaced_chain(label, new_chain)
    assert replaced.provenance.chain == new_chain
    assert replaced.spec_id == "d"


@pytest.mark.parametrize("n", [0, 1, 5])
def test_prefix_never_exceeds_available_steps(n: int) -> None:
    ap = _ap("x", "a", "b")
    assert len(ap.prefix(n).steps) <= len(ap.steps)
