# SPDX-License-Identifier: Apache-2.0
"""Witness construction, selection, and fingerprinting (``ENGINE_4``).

A finding's *witness* is the ordered ``source -> ... -> sink`` trace that proves
it (principle P2). This module is the single, deterministic (P3) authority on:

* :func:`better_chain` — pick the canonical witness when several reach one sink:
  **shortest** chain first, then the lexicographically smallest tuple of
  ``(role, file, line, column, end_line, end_column)`` step keys.
* :func:`witness_fingerprint` / :func:`finding_fingerprint` — stable ``sha256``
  hex digests derived **only** from field values (no ``id()`` / ``hash()`` /
  ``PYTHONHASHSEED`` dependence), so fingerprints are byte-identical across runs
  and machines.

It holds no taint, detector, or CWE knowledge — it operates purely on
:class:`~scanipy.models.WitnessStep` / :class:`~scanipy.models.Location` values.
"""

from __future__ import annotations

import hashlib

from scanipy.models import Location, WitnessRole, WitnessStep


def _step_key(step: WitnessStep) -> tuple[str, str, int, int, int, int]:
    """A total, value-only ordering key for one witness step (P3)."""
    loc = step.location
    return (
        step.role.value,
        loc.file,
        loc.line,
        loc.column,
        loc.end_line if loc.end_line is not None else -1,
        loc.end_column if loc.end_column is not None else -1,
    )


def _chain_key(
    chain: tuple[WitnessStep, ...],
) -> tuple[int, tuple[tuple[str, str, int, int, int, int], ...]]:
    """Selection key: shorter wins, then lexicographically smaller step keys."""
    return (len(chain), tuple(_step_key(step) for step in chain))


def better_chain(a: tuple[WitnessStep, ...], b: tuple[WitnessStep, ...]) -> tuple[WitnessStep, ...]:
    """Return the canonical of two witness chains (shortest, then smallest).

    Returns the *identity* of the chosen tuple (``is``-comparable), so callers can
    detect which side won. Ties (equal keys) keep ``a``.
    """
    if _chain_key(b) < _chain_key(a):
        return b
    return a


def make_step(role: WitnessRole, location: Location, description: str = "") -> WitnessStep:
    """Build one :class:`~scanipy.models.WitnessStep` (convenience constructor)."""
    return WitnessStep(role=role, location=location, description=description)


def build_witness(
    chain: tuple[WitnessStep, ...], sink_step: WitnessStep
) -> tuple[WitnessStep, ...]:
    """Append the final SINK step to a provenance chain to form a full witness."""
    return (*chain, sink_step)


def _loc_fields(loc: Location) -> str:
    """A canonical ``file:line:col:end_line:end_col`` string for a location."""
    end_line = loc.end_line if loc.end_line is not None else -1
    end_col = loc.end_column if loc.end_column is not None else -1
    return f"{loc.file}:{loc.line}:{loc.column}:{end_line}:{end_col}"


def witness_fingerprint(steps: tuple[WitnessStep, ...]) -> str:
    """A stable ``sha256`` hex digest over the ordered witness step tuples (P3)."""
    parts = [f"{step.role.value}|{_loc_fields(step.location)}" for step in steps]
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def finding_fingerprint(
    detector_id: str, cwe: str, sink: Location, steps: tuple[WitnessStep, ...]
) -> str:
    """A stable ``sha256`` hex digest identifying a finding (P3).

    Derived only from ``detector_id``, ``cwe``, the sink location, and the witness
    fingerprint — never from object identity or hash randomization.
    """
    canonical = "\n".join([detector_id, cwe, _loc_fields(sink), witness_fingerprint(steps)])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
