# SPDX-License-Identifier: Apache-2.0
"""scanipy taint analysis engine.

Public surface: the :class:`~scanipy.engine.taint.TaintEngine` (taint analysis
over an :class:`~scanipy.ir.IRModule`), the pure pattern :func:`match`/:func:`matches`
functions, and the deterministic fingerprinting helpers (P3). Detection knowledge
lives entirely in the YAML detector specs the engine consumes (P4).
"""

from __future__ import annotations

from scanipy.engine.matcher import MatchNode, MatchResult, match, matches
from scanipy.engine.summaries import compute_summaries
from scanipy.engine.taint import TaintEngine, analyze_function
from scanipy.engine.taint_state import AccessPath, AccessStep, TaintEnv, TaintLabel
from scanipy.engine.witness import (
    better_chain,
    finding_fingerprint,
    witness_fingerprint,
)

__all__ = [
    "AccessPath",
    "AccessStep",
    "MatchNode",
    "MatchResult",
    "TaintEngine",
    "TaintEnv",
    "TaintLabel",
    "analyze_function",
    "better_chain",
    "compute_summaries",
    "finding_fingerprint",
    "match",
    "matches",
    "witness_fingerprint",
]
