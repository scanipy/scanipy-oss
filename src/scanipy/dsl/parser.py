# SPDX-License-Identifier: Apache-2.0
"""Parse + validate taint-DSL YAML into a :class:`~scanipy.dsl.spec.DetectorSpec`.

0.1.0 scaffold: parsing is not implemented yet. The ``taint-engine`` and
``detector-author`` agents implement :func:`parse_spec` against
``docs/dsl-reference.md``, including the shape/closure validation that keeps
detectors declarative (principle P4) and rejects anything outside the DSL.
"""

from __future__ import annotations

from pathlib import Path

from scanipy.dsl.spec import DetectorSpec


class DSLError(ValueError):
    """A detector spec is not valid taint-DSL."""


def parse_spec(text: str, *, source_path: str | None = None) -> DetectorSpec:
    """Parse taint-DSL YAML text into a :class:`DetectorSpec`.

    Raises :class:`DSLError` on a spec that is syntactically valid YAML but not
    valid taint-DSL.
    """
    raise NotImplementedError(
        "taint-DSL parsing is not implemented in the 0.1.0 scaffold; "
        "see docs/dsl-reference.md and the taint-engine agent."
    )


def load_spec_file(path: str | Path) -> DetectorSpec:
    """Read and parse a detector spec file."""
    p = Path(path)
    return parse_spec(p.read_text(encoding="utf-8"), source_path=str(p))
