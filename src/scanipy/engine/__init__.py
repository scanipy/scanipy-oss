# SPDX-License-Identifier: Apache-2.0
"""scanipy taint analysis engine (0.1.0 scaffold)."""

from __future__ import annotations

from scanipy.engine.matcher import MatchNode, MatchResult, match, matches
from scanipy.engine.taint import TaintEngine

__all__ = ["MatchNode", "MatchResult", "TaintEngine", "match", "matches"]
