# SPDX-License-Identifier: Apache-2.0
"""Parsed detector spec (DRAFT / v0).

A :class:`DetectorSpec` is the in-memory form of one ``*.yml`` detector under
``scanipy/detectors/``. See ``docs/dsl-reference.md`` for the canonical schema.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from scanipy.dsl.patterns import Pattern, Propagator
from scanipy.models import Severity


@dataclass(frozen=True)
class DetectorSpec:
    """One declarative taint detector."""

    id: str
    name: str
    cwe: str
    severity: Severity
    languages: tuple[str, ...]
    message: str
    sources: tuple[Pattern, ...]
    sinks: tuple[Pattern, ...]
    sanitizers: tuple[Pattern, ...] = ()
    propagators: tuple[Propagator, ...] = ()
    metadata: Mapping[str, object] = field(default_factory=dict)
