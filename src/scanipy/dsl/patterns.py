# SPDX-License-Identifier: Apache-2.0
"""Taint-DSL pattern primitives (DRAFT / v0).

A :class:`Pattern` matches a syntactic site — a call, an attribute access, a
function parameter, or an import — using a dotted path with ``*`` wildcards.
Sources, sinks, and sanitizers are all expressed as patterns; a
:class:`Propagator` adds a :class:`Flow` describing how taint moves through a
call.

This schema is **draft** and co-evolves with the taint engine. The canonical,
field-by-field reference is ``docs/dsl-reference.md``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum


class PatternKind(str, Enum):
    """What kind of syntactic site a pattern matches."""

    CALL = "call"
    ATTRIBUTE = "attribute"
    PARAMETER = "parameter"
    IMPORT = "import"


@dataclass(frozen=True)
class Pattern:
    """A match against a call/attribute/parameter/import site.

    ``args`` optionally restricts a sink/sanitizer to specific positional
    argument indices; ``when`` carries extra constraints (e.g. a required
    keyword such as ``shell=True``).
    """

    kind: PatternKind
    pattern: str
    args: tuple[int, ...] | None = None
    when: Mapping[str, object] | None = None


@dataclass(frozen=True)
class Flow:
    """How taint moves through a propagator.

    ``from_`` and ``to`` use the DSL's flow vocabulary (e.g. ``"any-arg"``,
    ``"arg:0"``, ``"self"``, ``"return"``).
    """

    from_: str
    to: str


@dataclass(frozen=True)
class Propagator:
    """A call that carries taint from one position to another."""

    pattern: Pattern
    flow: Flow
