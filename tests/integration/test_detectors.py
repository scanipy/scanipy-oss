# SPDX-License-Identifier: Apache-2.0
"""Per-detector TP/TN enforcement matrix (DETECTOR_10, P5).

This is the catalog's correctness gate. It is **auto-parametrized from the real
detector pack** (:func:`load_builtin_detectors`) so every shipped detector is
covered without hand-listing it (P4): the test discovers what exists and demands
that each one carries a working true-positive and true-negative fixture.

Fixtures are paired by convention: a detector whose ``id`` ends in ``<stem>`` owns
``tests/fixtures/python/vulnerable/<stem>.py`` (which the engine MUST flag) and
``tests/fixtures/python/safe/<stem>.py`` (which it MUST NOT flag). For each
true-positive we assert at least one finding for that detector, with the spec's
own ``detector_id`` / ``cwe`` / ``severity`` and a non-empty witness ending in a
``SINK`` step (P2). For each true-negative we assert zero findings for that
detector.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scanipy.dsl import DetectorSpec
from scanipy.engine.taint import TaintEngine
from scanipy.frontends.python_frontend import PythonFrontend
from scanipy.models import Finding, WitnessRole
from scanipy.registry import load_builtin_detectors

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "python"

# The active catalog, sorted by id (deterministic — P3). Parametrizing over this
# makes the matrix grow automatically as detectors are added/shipped.
SPECS: tuple[DetectorSpec, ...] = load_builtin_detectors()


def _fixture_stem(spec: DetectorSpec) -> str:
    """The fixture file stem for a detector: the last dotted segment of its id."""
    return spec.id.split(".")[-1]


def _analyze(path: Path) -> list[Finding]:
    """Run the full production path (frontend + engine) over one file."""
    module = PythonFrontend().parse(path)
    assert module is not None, f"frontend failed to parse {path}"
    return TaintEngine(SPECS).analyze(module)


def _spec_id(spec: DetectorSpec) -> str:
    return spec.id


@pytest.mark.parametrize("spec", SPECS, ids=_spec_id)
def test_detector_true_positive_is_flagged(spec: DetectorSpec) -> None:
    """Each detector flags its vulnerable fixture with a witness ending in SINK."""
    fixture = FIXTURES / "vulnerable" / f"{_fixture_stem(spec)}.py"
    assert fixture.is_file(), f"missing true-positive fixture for {spec.id}: {fixture}"

    mine = [f for f in _analyze(fixture) if f.detector_id == spec.id]
    assert mine, f"{spec.id} produced no finding for its true-positive fixture"

    finding = mine[0]
    assert finding.cwe == spec.cwe
    assert finding.severity == spec.severity
    assert finding.message == spec.message
    assert finding.witness, "finding must carry a witness (P2)"
    assert finding.witness[0].role is WitnessRole.SOURCE
    assert finding.witness[-1].role is WitnessRole.SINK
    assert finding.fingerprint is not None and len(finding.fingerprint) == 64


@pytest.mark.parametrize("spec", SPECS, ids=_spec_id)
def test_detector_true_negative_is_clean(spec: DetectorSpec) -> None:
    """Each detector stays silent on its safe fixture (P5)."""
    fixture = FIXTURES / "safe" / f"{_fixture_stem(spec)}.py"
    assert fixture.is_file(), f"missing true-negative fixture for {spec.id}: {fixture}"

    mine = [f for f in _analyze(fixture) if f.detector_id == spec.id]
    assert mine == [], f"{spec.id} falsely flagged its true-negative fixture"


def test_every_detector_has_paired_fixtures() -> None:
    """Sanity: the matrix is non-empty and every detector is fixture-backed (P5)."""
    assert SPECS, "no detectors discovered"
    for spec in SPECS:
        stem = _fixture_stem(spec)
        assert (FIXTURES / "vulnerable" / f"{stem}.py").is_file(), spec.id
        assert (FIXTURES / "safe" / f"{stem}.py").is_file(), spec.id


# ---------------------------------------------------------------------------
# Interprocedural fixtures (DETECTOR_9) — exercise the engine's TITO summaries
# rather than the stem-paired per-detector matrix above. The taint crosses a
# function-call boundary (caller source -> callee parameter -> callee sink), so
# the witness is spliced across the call with a PROPAGATOR hop.
# ---------------------------------------------------------------------------


def test_interprocedural_true_positive_is_flagged() -> None:
    """Taint flowing through a callee's parameter into its sink is flagged."""
    findings = _analyze(FIXTURES / "vulnerable" / "interproc-os-command.py")
    cmd = [f for f in findings if f.detector_id == "python.injection.os-command"]
    assert len(cmd) == 1, "interprocedural os-command flow should be flagged once"

    witness = cmd[0].witness
    assert witness[0].role is WitnessRole.SOURCE
    assert witness[-1].role is WitnessRole.SINK
    # The call hop is spliced in as a PROPAGATOR step between source and sink.
    assert any(step.role is WitnessRole.PROPAGATOR for step in witness)


def test_interprocedural_true_negative_is_clean() -> None:
    """A callee that sanitizes its parameter before the sink yields no finding."""
    findings = _analyze(FIXTURES / "safe" / "interproc-path-traversal.py")
    assert findings == []
