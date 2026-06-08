# SPDX-License-Identifier: Apache-2.0
"""Detector registry — discovers the bundled detector specs.

The taint-DSL specs under ``scanipy/detectors/`` ship as package data. This
module locates and (eventually) parses them into :class:`~scanipy.dsl.DetectorSpec`
records. Detection logic lives entirely in those specs, not here (principle P4).

0.1.0 scaffold: :func:`discover_spec_files` already works; :func:`load_builtin_detectors`
returns an empty set until :func:`scanipy.dsl.parse_spec` lands (taint-engine agent).
"""

from __future__ import annotations

from pathlib import Path

from scanipy.dsl import DetectorSpec


def builtin_detectors_path() -> Path:
    """Filesystem path to the bundled detector specs directory."""
    return Path(__file__).resolve().parent / "detectors"


def discover_spec_files() -> tuple[Path, ...]:
    """Every bundled ``*.yml`` detector spec, sorted for determinism (P3)."""
    root = builtin_detectors_path()
    if not root.is_dir():
        return ()
    return tuple(sorted(root.rglob("*.yml")))


def load_builtin_detectors() -> tuple[DetectorSpec, ...]:
    """Parse and return every bundled detector spec.

    Stub: returns ``()`` until the DSL parser is implemented.
    """
    return ()
