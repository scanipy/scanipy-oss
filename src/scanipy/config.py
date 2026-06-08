# SPDX-License-Identifier: Apache-2.0
"""Scan configuration (file + CLI merge).

0.1.0 scaffold: :func:`load_config` returns defaults only. The ``cli-ux`` agent
wires ``.scanipy.yml`` / ``[tool.scanipy]`` discovery here. scanipy is
zero-config by design (principle P6): every option has a sensible default.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scanipy.models import Severity


@dataclass(frozen=True)
class ScanConfig:
    """Resolved scan options."""

    detectors: tuple[str, ...] = ()
    severity_threshold: Severity = Severity.LOW
    fail_on: Severity | None = None
    exclude: tuple[str, ...] = ()
    output_format: str = "text"


def load_config(path: str | Path | None = None) -> ScanConfig:
    """Load scan configuration, falling back to defaults.

    The 0.1.0 scaffold ignores any on-disk config and returns
    :class:`ScanConfig` defaults.
    """
    return ScanConfig()
