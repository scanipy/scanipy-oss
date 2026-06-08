# SPDX-License-Identifier: Apache-2.0
"""Reporter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from scanipy.models import Finding


class Reporter(ABC):
    """Renders a list of findings into a string for a given output format."""

    format_name: str

    @abstractmethod
    def render(self, findings: Sequence[Finding]) -> str:
        """Render ``findings`` to text in this reporter's format."""
