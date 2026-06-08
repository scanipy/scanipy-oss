# SPDX-License-Identifier: Apache-2.0
"""Tests for the pieces that already work in the 0.1.0 scaffold."""

from __future__ import annotations

import json

from scanipy.models import Finding, Location, Severity, WitnessRole, WitnessStep
from scanipy.registry import discover_spec_files
from scanipy.reporting import get_reporter


def test_bundled_specs_are_discoverable() -> None:
    specs = discover_spec_files()
    names = {p.name for p in specs}
    assert "os-command.yml" in names
    assert "sql.yml" in names


def test_reporters_handle_empty_findings() -> None:
    assert get_reporter("text").render([]) == "No findings."
    assert json.loads(get_reporter("json").render([]))["findings"] == []
    sarif = json.loads(get_reporter("sarif").render([]))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []


def test_reporters_render_a_finding() -> None:
    finding = Finding(
        detector_id="python.injection.os-command",
        cwe="CWE-78",
        severity=Severity.HIGH,
        message="tainted input reaches os.system",
        location=Location(file="app.py", line=10, column=4),
        witness=(
            WitnessStep(WitnessRole.SOURCE, Location("app.py", 8, 4), "input()"),
            WitnessStep(WitnessRole.SINK, Location("app.py", 10, 4), "os.system"),
        ),
    )

    text = get_reporter("text").render([finding])
    assert "CWE-78" in text
    assert "1 finding." in text

    payload = json.loads(get_reporter("json").render([finding]))
    assert payload["findings"][0]["detector_id"] == "python.injection.os-command"
    assert len(payload["findings"][0]["witness"]) == 2

    sarif = json.loads(get_reporter("sarif").render([finding]))
    assert sarif["runs"][0]["results"][0]["ruleId"] == "python.injection.os-command"
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_unknown_format_rejected() -> None:
    try:
        get_reporter("yaml")
    except ValueError:
        return
    raise AssertionError("expected ValueError for an unknown format")


def test_severity_ordering() -> None:
    assert Severity.CRITICAL.rank > Severity.LOW.rank
    assert Severity.from_str("HIGH") is Severity.HIGH
