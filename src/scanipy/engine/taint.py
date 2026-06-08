# SPDX-License-Identifier: Apache-2.0
"""Taint propagation engine (0.1.0 scaffold).

The engine takes a parsed module (from a language frontend) plus the active
detector specs and returns :class:`~scanipy.models.Finding` objects, each with
its ``source -> sink`` witness (P2). It is deterministic — same input + same
detector-pack version yields identical findings (P3) — and class-agnostic:
detection logic lives in the DSL specs, never here (P4).
"""

from __future__ import annotations

from collections.abc import Sequence

from scanipy.dsl import DetectorSpec
from scanipy.models import Finding


class TaintEngine:
    """Runs taint analysis for a set of detector specs."""

    def __init__(self, specs: Sequence[DetectorSpec]) -> None:
        self._specs: tuple[DetectorSpec, ...] = tuple(specs)

    @property
    def specs(self) -> tuple[DetectorSpec, ...]:
        return self._specs

    def analyze(self, module: object) -> list[Finding]:
        """Analyze one parsed module and return its findings."""
        raise NotImplementedError(
            "the taint engine is not implemented in the 0.1.0 scaffold; "
            "see the taint-engine agent and CLAUDE.md."
        )
