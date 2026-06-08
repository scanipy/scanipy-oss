# SPDX-License-Identifier: Apache-2.0
"""Detector registry — discovers and parses the bundled detector specs.

The taint-DSL specs under ``scanipy/detectors/`` ship as package data. This
module locates them and parses them into :class:`~scanipy.dsl.DetectorSpec`
records. Detection logic lives entirely in those specs, not here (principle P4).

:func:`load_builtin_detectors` parses every bundled spec in deterministic order
(P3), enforces globally-unique ids, and returns a tuple sorted by id.
"""

from __future__ import annotations

from pathlib import Path

from scanipy.dsl import DetectorSpec, DSLError, load_spec_file


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
    """Parse every bundled detector spec, sorted by id, with unique ids.

    Parses each path from :func:`discover_spec_files` (already sorted, so the
    parse order is deterministic — P3), enforces globally-unique detector ids to
    protect the engine from nondeterministic detector selection, and returns the
    specs as a tuple sorted by ``id``.

    Raises :class:`~scanipy.dsl.DSLError` if any spec is invalid or if two specs
    share an id.
    """
    seen: dict[str, Path] = {}
    specs: list[DetectorSpec] = []
    for path in discover_spec_files():
        spec = load_spec_file(path)
        if spec.id in seen:
            raise DSLError(
                f"duplicate detector id {spec.id!r} in {path} (already defined in {seen[spec.id]})",
                spec_id=spec.id,
                source_path=str(path),
            )
        seen[spec.id] = path
        specs.append(spec)
    return tuple(sorted(specs, key=lambda s: s.id))
