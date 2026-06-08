# SPDX-License-Identifier: Apache-2.0
"""Human-readable text reporter."""

from __future__ import annotations

from collections.abc import Sequence

from scanipy.models import Finding
from scanipy.reporting.base import Reporter


class TextReporter(Reporter):
    """Plain-text rendering, one block per finding with its witness trace."""

    format_name = "text"

    def render(self, findings: Sequence[Finding]) -> str:
        if not findings:
            return "No findings."

        lines: list[str] = []
        for finding in findings:
            loc = finding.location
            lines.append(
                f"{finding.severity.value.upper()} {finding.detector_id} "
                f"[{finding.cwe}] {loc.file}:{loc.line}:{loc.column}"
            )
            lines.append(f"    {finding.message}")
            for step in finding.witness:
                s = step.location
                trace = f"    - {step.role.value}: {s.file}:{s.line}:{s.column}"
                if step.description:
                    trace = f"{trace}  {step.description}"
                lines.append(trace)
            lines.append("")

        count = len(findings)
        lines.append(f"{count} finding{'s' if count != 1 else ''}.")
        return "\n".join(lines)
