# SPDX-License-Identifier: Apache-2.0
"""Reporters render findings in text, JSON, or SARIF."""

from __future__ import annotations

from scanipy.reporting.base import Reporter
from scanipy.reporting.json_reporter import JsonReporter
from scanipy.reporting.sarif import SarifReporter
from scanipy.reporting.text import TextReporter

_REPORTERS: dict[str, type[Reporter]] = {
    "text": TextReporter,
    "json": JsonReporter,
    "sarif": SarifReporter,
}


def get_reporter(output_format: str) -> Reporter:
    """Return a reporter instance for ``output_format`` (``text``/``json``/``sarif``)."""
    try:
        return _REPORTERS[output_format]()
    except KeyError as exc:
        raise ValueError(f"unknown report format {output_format!r}") from exc


__all__ = [
    "JsonReporter",
    "Reporter",
    "SarifReporter",
    "TextReporter",
    "get_reporter",
]
