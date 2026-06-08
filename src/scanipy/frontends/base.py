# SPDX-License-Identifier: Apache-2.0
"""Frontend interface.

A :class:`Frontend` turns a source file into a normalized module the taint
engine can analyze. Python is the first (and, in 0.1.0, only planned) frontend;
the interface exists so additional languages can be added without touching the
engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from scanipy.ir import IRModule


class Frontend(ABC):
    """Parses one language into the engine's normalized module form."""

    language: str

    @abstractmethod
    def parse(self, path: Path) -> IRModule | None:
        """Parse a source file into the shared IR, or ``None`` if it cannot be parsed."""
