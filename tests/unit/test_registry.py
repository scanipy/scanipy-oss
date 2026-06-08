# SPDX-License-Identifier: Apache-2.0
"""Tests for :mod:`scanipy.registry` — the bundled-detector loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanipy import registry
from scanipy.dsl import DSLError
from scanipy.registry import discover_spec_files, load_builtin_detectors


def test_load_builtin_detectors_parses_all_bundled() -> None:
    specs = load_builtin_detectors()
    assert len(specs) == len(discover_spec_files())
    assert len(specs) >= 2  # at least os-command + sql ship today.


def test_load_builtin_detectors_ids_unique() -> None:
    specs = load_builtin_detectors()
    ids = [s.id for s in specs]
    assert len(ids) == len(set(ids))


def test_load_builtin_detectors_sorted_by_id() -> None:
    specs = load_builtin_detectors()
    ids = [s.id for s in specs]
    assert ids == sorted(ids)


def test_every_bundled_spec_has_source_and_sink() -> None:
    for spec in load_builtin_detectors():
        assert spec.sources, f"{spec.id} has no sources"
        assert spec.sinks, f"{spec.id} has no sinks"


def test_load_builtin_detectors_deterministic() -> None:
    first = load_builtin_detectors()
    second = load_builtin_detectors()
    assert first == second


def test_known_bundled_ids_present() -> None:
    ids = {s.id for s in load_builtin_detectors()}
    assert "python.injection.os-command" in ids
    assert "python.injection.sql" in ids


def test_duplicate_id_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spec_text = (
        "id: python.test.dup\nname: Dup\ncwe: CWE-1\nseverity: low\n"
        "languages: [python]\nmessage: m\n"
        'sources:\n  - {{ kind: call, pattern: "input" }}\n'
        'sinks:\n  - {{ kind: call, pattern: "os.system" }}\n'
    )
    a = tmp_path / "a.yml"
    b = tmp_path / "b.yml"
    a.write_text(spec_text.replace("{{", "{").replace("}}", "}"), encoding="utf-8")
    b.write_text(spec_text.replace("{{", "{").replace("}}", "}"), encoding="utf-8")

    monkeypatch.setattr(registry, "discover_spec_files", lambda: (a, b))
    with pytest.raises(DSLError) as exc:
        load_builtin_detectors()
    assert "duplicate detector id" in str(exc.value)
    assert exc.value.spec_id == "python.test.dup"
