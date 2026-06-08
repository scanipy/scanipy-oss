# SPDX-License-Identifier: Apache-2.0
"""scanipy taint DSL (DRAFT / v0).

Detectors are declarative specs built from :class:`Pattern` sources, sinks, and
sanitizers, plus :class:`Propagator` flow rules. Canonical schema:
``docs/dsl-reference.md``.
"""

from __future__ import annotations

from scanipy.dsl.parser import DSLError, load_spec_file, parse_spec
from scanipy.dsl.patterns import Flow, Pattern, PatternKind, Propagator
from scanipy.dsl.spec import DetectorSpec

__all__ = [
    "DSLError",
    "DetectorSpec",
    "Flow",
    "Pattern",
    "PatternKind",
    "Propagator",
    "load_spec_file",
    "parse_spec",
]
