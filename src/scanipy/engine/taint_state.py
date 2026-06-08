# SPDX-License-Identifier: Apache-2.0
"""The access-path taint lattice (``ENGINE_3``).

Taint is tracked per *access path*: a base variable plus a bounded suffix of
attribute / constant-subscript steps (depth cap :data:`STEPS_CAP`). At the cap
the engine **over-approximates** by collapsing to the prefix — biasing toward
false positives, never false negatives (principle P5). The whole module is
detector-agnostic (P4): it moves opaque :class:`TaintLabel` values keyed by
``spec_id`` and never knows what any spec means.

The environment is an *immutable* mapping ``AccessPath -> frozenset[TaintLabel]``;
every operation returns a fresh :class:`TaintEnv`. Joins **union** label sets
(never intersect — the load-bearing P5 rule) and keep, per ``(access_path,
spec_id)``, the single deterministically-best provenance so the lattice has
finite height and the forward dataflow always reaches a fixpoint (P3).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from scanipy.engine.witness import better_chain
from scanipy.models import WitnessStep

# Access-path depth cap: at most this many attribute/subscript steps are tracked
# precisely; deeper paths collapse to this prefix and over-approximate (P5-safe).
STEPS_CAP = 2


@dataclass(frozen=True)
class AccessStep:
    """One hop of an access path: ``.attr`` or a constant ``[index]``.

    ``kind`` is ``"attr"`` or ``"index"``; ``value`` is the attribute name or the
    ``repr`` of the constant index (so ``x[0]`` and ``x["0"]`` stay distinct).
    """

    kind: str  # "attr" | "index"
    value: str


@dataclass(frozen=True)
class AccessPath:
    """A taint key: a base name plus a bounded tuple of :class:`AccessStep`.

    Equality / hashing / ordering are by ``(base, steps)`` — purely by value, so
    the lattice is deterministic (P3) and the path is usable as a dict key.
    """

    base: str
    steps: tuple[AccessStep, ...] = ()

    def prefix(self, n: int) -> AccessPath:
        """Return this path truncated to at most ``n`` leading steps."""
        if n < 0:
            n = 0
        return AccessPath(base=self.base, steps=self.steps[:n])

    def is_prefix_of(self, other: AccessPath) -> bool:
        """True if ``self`` is an (improper) access-path prefix of ``other``."""
        if self.base != other.base:
            return False
        if len(self.steps) > len(other.steps):
            return False
        return other.steps[: len(self.steps)] == self.steps

    def extend(self, step: AccessStep) -> AccessPath:
        """Append one step, collapsing to :data:`STEPS_CAP` (over-approximation)."""
        if len(self.steps) >= STEPS_CAP:
            return self  # already at the cap: stay collapsed (FP-biased, P5-safe)
        return AccessPath(base=self.base, steps=(*self.steps, step))

    def sort_key(self) -> tuple[str, tuple[tuple[str, str], ...]]:
        """A total, value-only ordering key for deterministic iteration (P3)."""
        return (self.base, tuple((s.kind, s.value) for s in self.steps))


@dataclass(frozen=True)
class TaintProvenance:
    """The accumulated witness chain behind a label, kept short and canonical.

    ``chain`` holds the ordered :class:`~scanipy.models.WitnessStep` steps from the
    SOURCE up to (but not including) the eventual SINK, which the engine appends at
    emission. Only the deterministically-best chain per ``(access_path, spec_id)``
    is retained (see :func:`~scanipy.engine.witness.better_chain`), bounding state.
    """

    spec_id: str
    chain: tuple[WitnessStep, ...]


@dataclass(frozen=True)
class TaintLabel:
    """One unit of taint: a ``spec_id`` plus its :class:`TaintProvenance`.

    Two labels are "the same vulnerability class" iff they share ``spec_id``; the
    environment keeps a single best provenance per ``(access_path, spec_id)``.
    """

    spec_id: str
    provenance: TaintProvenance


def _merge_labels(labels: frozenset[TaintLabel]) -> frozenset[TaintLabel]:
    """Collapse a label set to one best-provenance label per ``spec_id`` (P3)."""
    best: dict[str, TaintLabel] = {}
    for label in labels:
        existing = best.get(label.spec_id)
        if existing is None:
            best[label.spec_id] = label
            continue
        chosen = better_chain(existing.provenance.chain, label.provenance.chain)
        if chosen is label.provenance.chain:
            best[label.spec_id] = label
    return frozenset(best.values())


@dataclass(frozen=True)
class TaintEnv:
    """An immutable ``AccessPath -> frozenset[TaintLabel]`` taint environment.

    Every mutating operation returns a new :class:`TaintEnv`. A path is "tainted"
    when it (or a tracked prefix of it) carries a label; reads over-approximate up
    the prefix chain so a collapsed deep path taints its siblings (P5-safe).
    """

    _map: dict[AccessPath, frozenset[TaintLabel]] = field(default_factory=dict)

    def get(self, ap: AccessPath) -> frozenset[TaintLabel]:
        """Labels tainting ``ap``: its own labels plus those of any prefix path.

        Reading over-approximates: a label on a prefix (e.g. collapsed ``x.a``)
        flows to any extension read (``x.a.b``), biasing toward false positives.
        """
        out: set[TaintLabel] = set()
        for key, labels in self._map.items():
            if key.is_prefix_of(ap):
                out.update(labels)
        return _merge_labels(frozenset(out))

    def assign(self, ap: AccessPath, labels: frozenset[TaintLabel]) -> TaintEnv:
        """Kill ``ap`` (and its extensions) then bind ``labels`` at ``ap``.

        Reassigning ``x`` clears prior ``x.a`` taint (kill-then-seed); an empty
        ``labels`` leaves ``ap`` clean (the constant-reassignment case).
        """
        new_map = self._without(ap)
        merged = _merge_labels(labels)
        if merged:
            new_map[ap] = merged
        return TaintEnv(_map=new_map)

    def seed(self, ap: AccessPath, labels: frozenset[TaintLabel]) -> TaintEnv:
        """Add ``labels`` at ``ap`` without killing existing taint (union-add)."""
        if not labels:
            return self
        new_map = dict(self._map)
        new_map[ap] = _merge_labels(new_map.get(ap, frozenset()) | labels)
        return TaintEnv(_map=new_map)

    def kill(self, ap: AccessPath) -> TaintEnv:
        """Remove all labels at ``ap`` and at any proper extension of ``ap``."""
        return TaintEnv(_map=self._without(ap))

    def sanitize(self, ap: AccessPath, spec_id: str) -> TaintEnv:
        """Remove ``spec_id`` labels at ``ap`` and its extensions (one-sided, P5).

        Other specs' labels and other paths are untouched; sanitization only ever
        removes taint on the path where the sanitizer demonstrably runs.
        """
        new_map: dict[AccessPath, frozenset[TaintLabel]] = {}
        for key, labels in self._map.items():
            if ap.is_prefix_of(key):
                kept = frozenset(label for label in labels if label.spec_id != spec_id)
                if kept:
                    new_map[key] = kept
            else:
                new_map[key] = labels
        return TaintEnv(_map=new_map)

    def join(self, other: TaintEnv) -> TaintEnv:
        """Per-path **union** with ``other``, keeping the best provenance (P5/P3).

        Union never intersects: a path tainted on only one incoming branch stays
        tainted at the join (the load-bearing P5 rule).
        """
        new_map: dict[AccessPath, frozenset[TaintLabel]] = dict(self._map)
        for key, labels in other._map.items():
            new_map[key] = _merge_labels(new_map.get(key, frozenset()) | labels)
        return TaintEnv(_map=new_map)

    def is_empty(self) -> bool:
        """True if no path carries any taint."""
        return not self._map

    def items(self) -> tuple[tuple[AccessPath, frozenset[TaintLabel]], ...]:
        """All ``(path, labels)`` pairs, sorted by path for determinism (P3)."""
        return tuple(sorted(self._map.items(), key=lambda kv: kv[0].sort_key()))

    def _without(self, ap: AccessPath) -> dict[AccessPath, frozenset[TaintLabel]]:
        """A copy of the backing map with ``ap`` and its extensions removed."""
        return {key: labels for key, labels in self._map.items() if not ap.is_prefix_of(key)}

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TaintEnv):
            return NotImplemented
        return self._map == other._map


def empty_env() -> TaintEnv:
    """A fresh empty :class:`TaintEnv`."""
    return TaintEnv()


def with_replaced_chain(label: TaintLabel, chain: tuple[WitnessStep, ...]) -> TaintLabel:
    """Return ``label`` with a new provenance ``chain`` (provenance is frozen)."""
    return replace(label, provenance=replace(label.provenance, chain=chain))
