# SPDX-License-Identifier: Apache-2.0
"""Core finding model.

A :class:`Finding` always carries its taint *witness* — the
``source -> ... -> sink`` trace that justifies it (principle P2). The model is
deliberately engine-agnostic so the taint engine, the detector specs, and the
reporters can all share it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """Ordered finding severity."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank for threshold comparisons (``LOW`` is lowest)."""
        return _SEVERITY_RANK[self]

    @classmethod
    def from_str(cls, value: str) -> Severity:
        """Parse a severity name case-insensitively."""
        try:
            return cls(value.lower())
        except ValueError as exc:  # pragma: no cover - trivial
            raise ValueError(f"unknown severity {value!r}") from exc


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class WitnessRole(str, Enum):
    """The role a node plays in a taint witness."""

    SOURCE = "source"
    PROPAGATOR = "propagator"
    SANITIZER = "sanitizer"
    SINK = "sink"


@dataclass(frozen=True)
class Location:
    """A position in a source file (1-based line, 0-based column)."""

    file: str
    line: int
    column: int = 0
    end_line: int | None = None
    end_column: int | None = None


@dataclass(frozen=True)
class WitnessStep:
    """One hop in the ``source -> ... -> sink`` trace behind a finding."""

    role: WitnessRole
    location: Location
    description: str = ""


@dataclass(frozen=True)
class Finding:
    """A single reported vulnerability.

    ``location`` points at the sink (the dangerous use); ``witness`` records the
    full data-flow trace that reaches it.
    """

    detector_id: str
    cwe: str
    severity: Severity
    message: str
    location: Location
    witness: tuple[WitnessStep, ...] = ()
    fingerprint: str | None = None

    def to_dict(self) -> dict[str, object]:
        """A JSON-serializable view of the finding."""
        return {
            "detector_id": self.detector_id,
            "cwe": self.cwe,
            "severity": self.severity.value,
            "message": self.message,
            "location": _location_dict(self.location),
            "witness": [
                {
                    "role": step.role.value,
                    "location": _location_dict(step.location),
                    "description": step.description,
                }
                for step in self.witness
            ],
            "fingerprint": self.fingerprint,
        }


def _location_dict(loc: Location) -> dict[str, object]:
    return {
        "file": loc.file,
        "line": loc.line,
        "column": loc.column,
        "end_line": loc.end_line,
        "end_column": loc.end_column,
    }
