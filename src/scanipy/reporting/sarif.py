# SPDX-License-Identifier: Apache-2.0
"""SARIF 2.1.0 reporter — for GitHub code scanning and other SARIF consumers."""

from __future__ import annotations

import json
from collections.abc import Sequence

from scanipy import __version__
from scanipy.models import Finding, Severity
from scanipy.reporting.base import Reporter

_SARIF_LEVEL: dict[Severity, str] = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

_INFORMATION_URI = "https://github.com/scanipy/scanipy-oss"


class SarifReporter(Reporter):
    """Renders findings as a minimal, valid SARIF 2.1.0 log."""

    format_name = "sarif"

    def render(self, findings: Sequence[Finding]) -> str:
        results: list[dict[str, object]] = []
        for finding in findings:
            results.append(
                {
                    "ruleId": finding.detector_id,
                    "level": _SARIF_LEVEL[finding.severity],
                    "message": {"text": finding.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.location.file},
                                "region": {
                                    "startLine": finding.location.line,
                                    "startColumn": max(finding.location.column, 1),
                                },
                            }
                        }
                    ],
                }
            )

        log: dict[str, object] = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "scanipy",
                            "version": __version__,
                            "informationUri": _INFORMATION_URI,
                            "rules": [],
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(log, indent=2)
