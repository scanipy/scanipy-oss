# SPDX-License-Identifier: Apache-2.0
"""The pattern matcher: does one DSL :class:`Pattern` match one IR node?

This is the single place that interprets the taint DSL's dotted-path ``*``
wildcard grammar and the ``args`` / ``when`` constraints against the normalized
IR produced by the frontend (:mod:`scanipy.ir`). It is a **pure, deterministic**
function library (principle P3): given the same ``(Pattern, node)`` it always
returns an equal result. It performs no I/O, holds no mutable state, never
touches ``ast``, never consults taint state, and never builds witnesses — the
engine drives all of that downstream.

It is also the concrete realization of P4 (declarative detectors): the engine
asks "does this spec's pattern match here?" and gets a structural yes/no plus the
positional argument indices to check, with zero per-detector code.

The matcher consumes the *real* IR node types from :mod:`scanipy.ir`,
dispatched by the pattern's :class:`~scanipy.dsl.patterns.PatternKind`:

============  =====================  =========================================
Pattern kind  IR node type           Dotted name source
============  =====================  =========================================
``call``      :class:`~scanipy.ir.IRCall`        ``callee_path``
``attribute`` :class:`~scanipy.ir.IRAttribute`   ``canonical``
``import``    :class:`~scanipy.ir.ImportEntry`   ``canonical``
``parameter`` :class:`~scanipy.ir.IRParam`       ``name``
============  =====================  =========================================

A pattern only ever matches its own node type (the *kind gate*): a ``call``
pattern never matches an attribute/import/parameter node and vice versa. A
``None`` (unresolved) dotted name always yields no match and never raises.

The wildcard and constraint semantics pinned here are the single source of truth
together with ``docs/dsl-reference.md`` (kept in sync with this module).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from scanipy.dsl.patterns import Pattern, PatternKind
from scanipy.ir import ImportEntry, IRAttribute, IRCall, IRLiteral, IRParam

# The IR node types this matcher accepts. Other expression/statement nodes never
# reach the matcher; if one does, the kind gate returns ``None`` rather than
# raising (the "never raises on unexpected input" contract).
MatchNode = IRCall | IRAttribute | ImportEntry | IRParam

__all__ = ["MatchNode", "MatchResult", "match", "matches"]


@dataclass(frozen=True)
class MatchResult:
    """The positive result of a successful :func:`match`.

    ``dotted_name`` is the concrete resolved name that matched (a good witness
    description for P2, e.g. ``"subprocess.run"`` even when the pattern was the
    wildcard ``"subprocess.*"``). ``arg_indices`` are the sorted, de-duplicated,
    in-scope **positional** argument indices the engine must check for taint at a
    sink/sanitizer/propagator; they exclude the receiver and are ``()`` for any
    non-call kind.
    """

    dotted_name: str
    arg_indices: tuple[int, ...]


def match(pattern: Pattern, node: MatchNode) -> MatchResult | None:
    """Return a :class:`MatchResult` if ``pattern`` matches ``node``, else ``None``.

    The decision is, in order:

    1. **Kind gate** — ``pattern.kind`` must select the matching IR node type
       (``call`` -> :class:`~scanipy.ir.IRCall`, etc.); otherwise ``None``.
    2. **Name gate** — the node's canonical dotted name must be non-``None`` and
       match ``pattern.pattern`` under the wildcard grammar (:func:`_match_dotted`).
       A ``None`` dotted name yields ``None`` and never raises.
    3. **Constraints** (``call`` only) — ``when`` must hold (:func:`_match_when`),
       and ``args`` must resolve to a non-empty set of in-range indices when a
       restriction is given (:func:`_resolve_arg_indices`); an out-of-range-only
       restriction is no match. ``args``/``when`` are ignored on non-call kinds.

    The function is pure: identical inputs always produce an equal result (P3).
    """
    kind = pattern.kind

    if kind is PatternKind.CALL:
        if not isinstance(node, IRCall):
            return None
        return _match_call(pattern, node)

    if kind is PatternKind.ATTRIBUTE:
        if not isinstance(node, IRAttribute):
            return None
        return _match_named(pattern, node.canonical)

    if kind is PatternKind.IMPORT:
        if not isinstance(node, ImportEntry):
            return None
        return _match_named(pattern, node.canonical)

    if kind is PatternKind.PARAMETER:
        if not isinstance(node, IRParam):
            return None
        # A parameter is always a resolved bare name; match the wildcard grammar
        # against it (v1 default — see docs/dsl-reference.md).
        return _match_named(pattern, node.name)

    return None  # pragma: no cover - exhaustive over PatternKind


def matches(pattern: Pattern, node: MatchNode) -> bool:
    """Convenience boolean wrapper: ``match(pattern, node) is not None``."""
    return match(pattern, node) is not None


def _match_named(pattern: Pattern, dotted_name: str | None) -> MatchResult | None:
    """Name-gate a non-call node (``args``/``when`` do not apply).

    Returns a :class:`MatchResult` with empty ``arg_indices`` on a name match, or
    ``None`` when the name is unresolved or does not match the pattern.
    """
    if dotted_name is None:
        return None
    if not _match_dotted(pattern.pattern, dotted_name):
        return None
    return MatchResult(dotted_name=dotted_name, arg_indices=())


def _match_call(pattern: Pattern, node: IRCall) -> MatchResult | None:
    """Name-gate + ``when`` + ``args`` for a :class:`~scanipy.ir.IRCall`."""
    dotted_name = node.callee_path
    if dotted_name is None:
        return None
    if not _match_dotted(pattern.pattern, dotted_name):
        return None

    if pattern.when is not None and not _match_when(pattern.when, node):
        return None

    arg_indices = _resolve_arg_indices(pattern.args, len(node.args))
    if pattern.args is not None and not arg_indices:
        # The restriction names only out-of-range indices, so this site cannot
        # carry the targeted taint -> no match (never widen to "all args").
        return None

    return MatchResult(dotted_name=dotted_name, arg_indices=arg_indices)


def _match_dotted(pattern: str, name: str) -> bool:
    """Segment-wise dotted-path match with a single ``*`` wildcard.

    Both strings are split on ``"."`` into segment lists; matching is pure list
    comparison (never regex/glob over the raw string), so it is deterministic and
    immune to substring surprises (``*.execute`` never matches ``executemany``).

    Three modes, dispatched by where ``*`` appears (the parser rejects any other
    ``*`` placement, e.g. multiple ``*`` or ``os.sys*``):

    * **EXACT** (no ``*``): match iff the segment lists are equal. ``os.system``
      matches only ``os.system``; bare ``input`` matches only ``input`` (not
      ``mymod.input``).
    * **TRAILING-SINGLE** (``*`` is the last and only wildcard segment): the
      literal prefix must match and ``*`` consumes **exactly one** segment. So
      ``subprocess.*`` matches ``subprocess.run`` but not ``subprocess.run.foo``
      or bare ``subprocess``; ``flask.request.*`` matches ``flask.request.args``
      but not ``flask.request.args.get``.
    * **LEADING-GREEDY** (``*`` is the first and only wildcard segment): the
      literal suffix must equal the tail of the name and ``*`` consumes
      **one-or-more** segments. So ``*.execute`` matches ``db.execute`` and
      ``self.db.cursor.execute``; ``*.cursor.execute`` matches
      ``self.db.cursor.execute`` but not ``self.db.execute``.

    Defensive on malformed input the parser is expected to reject: an empty
    pattern, or a ``*`` anywhere other than a lone leading/trailing segment,
    returns ``False`` (never widens, never raises).
    """
    if not pattern:
        return False

    p = pattern.split(".")
    n = name.split(".")

    star_positions = [i for i, seg in enumerate(p) if seg == "*"]

    if not star_positions:
        return p == n

    if len(star_positions) != 1:
        # Multiple wildcards are unsupported; the parser rejects them, but the
        # matcher refuses to guess rather than over-match.
        return False

    star = star_positions[0]

    if star == len(p) - 1:
        # TRAILING-SINGLE: prefix must match and '*' consumes exactly one segment.
        prefix = p[:-1]
        return len(n) == len(p) and n[: len(prefix)] == prefix

    if star == 0:
        # LEADING-GREEDY: suffix must equal the tail and '*' consumes >= 1 segment.
        suffix = p[1:]
        return len(n) > len(suffix) and n[-len(suffix) :] == suffix

    # A '*' in the middle (e.g. "a.*.c") is unsupported.
    return False


def _resolve_arg_indices(spec_args: tuple[int, ...] | None, arg_count: int) -> tuple[int, ...]:
    """Resolve the positional argument indices a call pattern restricts to.

    Indices are 0-based and **exclude the receiver** (``args: [0]`` on a method
    sink targets the first *written* argument, not the receiver — which is
    addressed as ``self`` in the flow vocabulary).

    * ``spec_args is None`` -> every written positional index, ``range(arg_count)``.
    * otherwise -> the sorted, de-duplicated intersection of ``spec_args`` with
      ``range(arg_count)`` (negatives and out-of-range indices are dropped).

    An empty result with a non-``None`` ``spec_args`` signals an out-of-range-only
    restriction; :func:`_match_call` turns that into a no-match.
    """
    if spec_args is None:
        return tuple(range(arg_count))
    return tuple(sorted({i for i in spec_args if 0 <= i < arg_count}))


def _match_when(when: Mapping[str, object], node: IRCall) -> bool:
    """Evaluate a call pattern's ``when`` constraint (literal-equality only).

    v1 supports exactly one ``when`` key, ``keyword``, whose value is a mapping of
    ``{kwarg-name: expected-literal}``. For each pair the call must pass that
    keyword as a **constant literal** equal to the expected value
    (``shell=True`` matches only a literal ``True``; ``shell=False``, an absent
    ``shell``, or ``shell=<variable>`` do not). All pairs are ANDed.

    Keys are iterated in sorted order for determinism. Any unknown top-level
    ``when`` key returns ``False`` (conservative: a malformed/unsupported
    constraint can never silently *widen* matches; the parser is the real gate).
    """
    literals = _literal_keywords(node)
    for key in sorted(when):
        if key != "keyword":
            return False
        spec = when[key]
        if not isinstance(spec, Mapping):
            return False
        for kw_name in sorted(spec):
            if kw_name not in literals:
                return False
            if literals[kw_name] != spec[kw_name]:
                return False
    return True


def _literal_keywords(node: IRCall) -> dict[str, object]:
    """Map each constant-literal keyword argument name to its literal value.

    Non-literal keywords (variables, calls), ``**kwargs`` splats (``name`` is
    ``None``), and non-constant literals are excluded, so a name present here is
    guaranteed to be a genuine compile-time constant for the ``when`` check.
    """
    out: dict[str, object] = {}
    for kw in node.kwargs:
        if kw.name is None:
            continue
        value = kw.value
        if isinstance(value, IRLiteral) and value.is_constant:
            out[kw.name] = value.value
    return out
