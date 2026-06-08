# SPDX-License-Identifier: Apache-2.0
"""JSON reporter — stable, machine-readable output."""

from __future__ import annotations

import json
from collections.abc import Sequence

from scanipy import __version__
from scanipy.models import Finding
from scanipy.reporting.base import Reporter


class JsonReporter(Reporter):
    """Renders findings as a deterministic JSON document (P3)."""

    format_name = "json"

    def render(self, findings: Sequence[Finding]) -> str:
        payload: dict[str, object] = {
            "tool": "scanipy",
            "version": __version__,
            "findings": [finding.to_dict() for finding in findings],
        }
        return json.dumps(payload, indent=2, sort_keys=True)
