# SPDX-License-Identifier: Apache-2.0
"""Tests for the taint-DSL parser (:mod:`scanipy.dsl.parser`).

Covers the happy path, every documented rejection, source-location precision,
the ``parameter``/``import`` kinds, keyword-value coercion, and determinism.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scanipy.dsl import (
    DetectorSpec,
    DSLError,
    Flow,
    Pattern,
    PatternKind,
    Propagator,
    parse_spec,
)
from scanipy.dsl.parser import load_spec_file
from scanipy.models import Severity

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "dsl"
_VALID = _FIXTURES / "valid"
_INVALID = _FIXTURES / "invalid"

_DETECTORS = Path(__file__).resolve().parent.parent.parent / "src" / "scanipy" / "detectors"


_MINIMAL = """
id: python.test.minimal
name: Minimal
cwe: CWE-78
severity: low
languages: [python]
message: A minimal spec.
sources:
  - { kind: call, pattern: "input" }
sinks:
  - { kind: call, pattern: "os.system", args: [0] }
"""


def _spec(**overrides: str) -> str:
    """Return YAML for a minimal valid spec with optional line overrides."""
    base = {
        "id": "python.test.x",
        "name": "X",
        "cwe": "CWE-78",
        "severity": "low",
        "languages": "[python]",
        "message": "msg",
    }
    base.update(overrides)
    head = "\n".join(f"{k}: {v}" for k, v in base.items())
    return (
        head
        + '\nsources:\n  - { kind: call, pattern: "input" }'
        + '\nsinks:\n  - { kind: call, pattern: "os.system" }\n'
    )


def _with_propagator(inline: str) -> str:
    """Append a single propagator (given as inline-mapping body) to a spec."""
    return _MINIMAL + f"propagators:\n  - {{ {inline} }}\n"


# --------------------------------------------------------------------------- #
# Happy path.
# --------------------------------------------------------------------------- #
def test_parse_minimal_valid_spec() -> None:
    spec = parse_spec(_MINIMAL)
    assert isinstance(spec, DetectorSpec)
    assert spec.id == "python.test.minimal"
    assert spec.severity is Severity.LOW
    assert spec.languages == ("python",)
    assert spec.sources == (Pattern(kind=PatternKind.CALL, pattern="input"),)
    assert spec.sinks == (Pattern(kind=PatternKind.CALL, pattern="os.system", args=(0,)),)
    assert spec.sanitizers == ()
    assert spec.propagators == ()
    assert dict(spec.metadata) == {}


def test_parse_full_fixture_roundtrip() -> None:
    spec = load_spec_file(_VALID / "full.yml")
    assert spec.severity is Severity.CRITICAL
    # wildcard + when keyword bool
    sub = next(p for p in spec.sinks if p.pattern == "subprocess.*")
    assert sub.when is not None
    assert sub.when["keyword"] == {"shell": True}
    # args are sorted + de-duplicated.
    exec_sink = next(p for p in spec.sinks if p.pattern == "*.cursor.execute")
    assert exec_sink.args == (0, 1)
    # propagator flow tokens.
    flows = {pr.pattern.pattern: (pr.flow.from_, pr.flow.to) for pr in spec.propagators}
    assert flows["str.format"] == ("any-arg", "return")
    assert flows["os.path.join"] == ("arg:0", "return")
    assert flows["shutil.copy"] == ("self", "return")
    # metadata preserves order + nesting, lists become tuples.
    assert spec.metadata["owasp"] == "A03:2021-Injection"
    assert spec.metadata["nested"]["flag"] is True
    assert spec.metadata["nested"]["count"] == 3
    assert isinstance(spec.metadata["references"], tuple)


# --------------------------------------------------------------------------- #
# Bundled specs.
# --------------------------------------------------------------------------- #
def test_parse_bundled_os_command() -> None:
    spec = load_spec_file(_DETECTORS / "injection" / "os-command.yml")
    assert spec.id == "python.injection.os-command"
    assert spec.cwe == "CWE-78"
    assert Pattern(kind=PatternKind.ATTRIBUTE, pattern="flask.request.*") in spec.sources
    assert Pattern(kind=PatternKind.CALL, pattern="os.system", args=(0,)) in spec.sinks
    sub = next(p for p in spec.sinks if p.pattern == "subprocess.*")
    assert sub.when is not None and sub.when["keyword"] == {"shell": True}
    assert spec.sanitizers == (Pattern(kind=PatternKind.CALL, pattern="shlex.quote"),)
    assert (
        Propagator(
            pattern=Pattern(kind=PatternKind.CALL, pattern="str.format"),
            flow=Flow(from_="any-arg", to="return"),
        )
        in spec.propagators
    )


def test_parse_bundled_sql() -> None:
    spec = load_spec_file(_DETECTORS / "injection" / "sql.yml")
    assert spec.id == "python.injection.sql"
    assert spec.sanitizers == ()
    assert Pattern(kind=PatternKind.CALL, pattern="*.cursor.execute", args=(0,)) in spec.sinks


# --------------------------------------------------------------------------- #
# Required / optional fields.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "field",
    ["id", "name", "cwe", "severity", "languages", "message", "sources", "sinks"],
)
def test_missing_required_field(field: str) -> None:
    lines = _MINIMAL.strip().splitlines()
    # Drop the line(s) for the field. Pattern lists span multiple lines.
    kept: list[str] = []
    skipping = False
    for line in lines:
        if line.startswith(f"{field}:"):
            skipping = True
            continue
        if skipping and (line.startswith("  ") or line.startswith("-")):
            continue
        skipping = False
        kept.append(line)
    text = "\n".join(kept) + "\n"
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert exc.value.field == field


def test_empty_sanitizers_ok() -> None:
    spec = parse_spec(_MINIMAL + "sanitizers: []\n")
    assert spec.sanitizers == ()


def test_missing_sanitizers_never_raises() -> None:
    # P5: a missing sanitizer must never raise.
    spec = parse_spec(_MINIMAL)
    assert spec.sanitizers == ()


# --------------------------------------------------------------------------- #
# Enums / scalar typing.
# --------------------------------------------------------------------------- #
def test_bad_severity() -> None:
    with pytest.raises(DSLError) as exc:
        parse_spec(_spec(severity="catastrophic"))
    assert exc.value.field == "severity"
    assert "low|medium|high|critical" in exc.value.message


def test_bool_severity_rejected() -> None:
    # `severity: yes` is a YAML bool, not the string "yes".
    with pytest.raises(DSLError) as exc:
        parse_spec(_spec(severity="yes"))
    assert exc.value.field == "severity"


@pytest.mark.parametrize("value", ["low", "medium", "high", "critical"])
def test_severity_values_accepted(value: str) -> None:
    spec = parse_spec(_spec(severity=value))
    assert spec.severity is Severity.from_str(value)


def test_bad_cwe() -> None:
    with pytest.raises(DSLError) as exc:
        parse_spec(_spec(cwe="CWE_78"))
    assert exc.value.field == "cwe"


def test_unsupported_language() -> None:
    with pytest.raises(DSLError) as exc:
        parse_spec(_spec(languages="[javascript]"))
    assert exc.value.field == "languages"
    assert "python" in exc.value.message


# --------------------------------------------------------------------------- #
# Unknown keys.
# --------------------------------------------------------------------------- #
def test_unknown_top_level_key_rejected() -> None:
    with pytest.raises(DSLError) as exc:
        parse_spec(_MINIMAL + "bogus: 1\n")
    assert exc.value.field == "bogus"
    assert "unknown top-level field" in exc.value.message


def test_unknown_pattern_kind_rejected() -> None:
    text = _spec()
    text = text.replace('kind: call, pattern: "input"', 'kind: gadget, pattern: "input"')
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "unknown pattern kind" in exc.value.message


def test_unknown_pattern_field_rejected() -> None:
    text = _spec().replace('kind: call, pattern: "input"', 'kind: call, pattern: "input", bogus: 1')
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "unknown pattern field" in exc.value.message


# --------------------------------------------------------------------------- #
# Dotted-pattern grammar.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "pattern",
    ["os.system", "subprocess.*", "*.cursor.execute", "flask.request.*", "input", "*"],
)
def test_dotted_pattern_accepts(pattern: str) -> None:
    text = _spec().replace('pattern: "os.system"', f'pattern: "{pattern}"')
    spec = parse_spec(text)
    assert any(p.pattern == pattern for p in spec.sinks)


@pytest.mark.parametrize(
    "pattern",
    ["", "os..system", ".os", "os.", "os system", "os.sys(tem)", "os[0]", "os.sys*"],
)
def test_dotted_pattern_rejects(pattern: str) -> None:
    text = _spec().replace('pattern: "os.system"', f'pattern: "{pattern}"')
    with pytest.raises(DSLError):
        parse_spec(text)


@pytest.mark.parametrize(
    "pattern",
    ["os.system", "subprocess.*", "*.execute", "*.cursor.execute", "flask.request.*", "input"],
)
def test_wildcard_placement_accepts_valid(pattern: str) -> None:
    # '*' as a single whole leading or trailing segment (and no-wildcard patterns)
    # all stay valid.
    text = _spec().replace('pattern: "os.system"', f'pattern: "{pattern}"')
    spec = parse_spec(text)
    assert any(p.pattern == pattern for p in spec.sinks)


@pytest.mark.parametrize(
    "pattern",
    ["os.*.system", "a.*.c", "*.*", "*.a.*"],
)
def test_wildcard_placement_rejected(pattern: str) -> None:
    # A mid-segment '*' or more than one '*' would silently never match, so the
    # parser rejects it at load time (P5/P7: no silently-dead rules). All four
    # pass the dotted-shape regex and fail only the placement check, so they share
    # the wildcard-placement message.
    text = _spec().replace('pattern: "os.system"', f'pattern: "{pattern}"')
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "may appear only once" in exc.value.message


# --------------------------------------------------------------------------- #
# args.
# --------------------------------------------------------------------------- #
def test_args_only_on_call() -> None:
    text = _spec().replace(
        'kind: call, pattern: "input"', 'kind: attribute, pattern: "flask.request.args", args: [0]'
    )
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "only valid on kind: call" in exc.value.message


def test_args_sorted_and_deduplicated() -> None:
    text = _spec().replace('pattern: "os.system"', 'pattern: "os.system", args: [2, 0, 2, 1]')
    spec = parse_spec(text)
    sink = next(p for p in spec.sinks if p.pattern == "os.system")
    assert sink.args == (0, 1, 2)


@pytest.mark.parametrize("args", ["[-1]", '["x"]', "[]", "[1.5]", "[010]", "[1:30]"])
def test_args_invalid(args: str) -> None:
    text = _spec().replace('pattern: "os.system"', f'pattern: "os.system", args: {args}')
    with pytest.raises(DSLError):
        parse_spec(text)


# --------------------------------------------------------------------------- #
# when.
# --------------------------------------------------------------------------- #
def test_when_only_on_call() -> None:
    text = _spec().replace(
        'kind: call, pattern: "input"',
        'kind: attribute, pattern: "flask.request.args", when: { keyword: { x: 1 } }',
    )
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "only valid on kind: call" in exc.value.message


def test_when_unknown_condition_rejected() -> None:
    text = _spec().replace(
        'pattern: "os.system"', 'pattern: "subprocess.run", when: { argument: { shell: true } }'
    )
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "keyword" in exc.value.message


def test_when_non_scalar_value_rejected() -> None:
    text = _spec().replace(
        'pattern: "os.system"', 'pattern: "subprocess.run", when: { keyword: { env: [1, 2] } }'
    )
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "scalar" in exc.value.message


def test_when_keyword_bool_vs_str_distinguished() -> None:
    boolean = _spec().replace(
        'pattern: "os.system"', 'pattern: "subprocess.run", when: { keyword: { shell: true } }'
    )
    string = _spec().replace(
        'pattern: "os.system"', "pattern: \"subprocess.run\", when: { keyword: { shell: 'true' } }"
    )
    bspec = parse_spec(boolean)
    sspec = parse_spec(string)
    bsink = next(p for p in bspec.sinks if p.pattern == "subprocess.run")
    ssink = next(p for p in sspec.sinks if p.pattern == "subprocess.run")
    assert bsink.when is not None and bsink.when["keyword"] == {"shell": True}
    assert ssink.when is not None and ssink.when["keyword"] == {"shell": "true"}


# --------------------------------------------------------------------------- #
# Flow vocabulary.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("token", ["any-arg", "self", "return", "arg:0", "arg:3"])
def test_flow_token_accepted(token: str) -> None:
    text = _with_propagator(f'kind: call, pattern: "f", flow: {{ from: {token}, to: return }}')
    spec = parse_spec(text)
    assert spec.propagators[0].flow.from_ == token


@pytest.mark.parametrize("token", ["arg:x", "returns", "", "arg:", "ARG:0"])
def test_flow_token_rejected(token: str) -> None:
    text = _with_propagator(f'kind: call, pattern: "f", flow: {{ from: "{token}", to: return }}')
    with pytest.raises(DSLError):
        parse_spec(text)


def test_flow_from_maps_to_dataclass_field() -> None:
    text = _with_propagator('kind: call, pattern: "f", flow: { from: any-arg, to: return }')
    spec = parse_spec(text)
    assert spec.propagators[0].flow.from_ == "any-arg"
    assert spec.propagators[0].flow.to == "return"


def test_propagator_must_be_call() -> None:
    text = _with_propagator('kind: attribute, pattern: "x.y", flow: { from: any-arg, to: return }')
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "kind: call" in exc.value.message


def test_propagator_missing_flow_rejected() -> None:
    text = _with_propagator('kind: call, pattern: "f"')
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "flow" in exc.value.message


def test_propagator_unknown_flow_key_rejected() -> None:
    text = _with_propagator('kind: call, pattern: "f", flow: { from: any-arg, to: return, via: x }')
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "flow" in exc.value.message


# --------------------------------------------------------------------------- #
# parameter / import kinds.
# --------------------------------------------------------------------------- #
def test_parameter_kind_valid() -> None:
    spec = load_spec_file(_VALID / "parameter-kind.yml")
    assert spec.sources[0].kind is PatternKind.PARAMETER
    assert {p.pattern for p in spec.sources} == {"request", "handler.request"}


def test_import_kind_valid() -> None:
    spec = load_spec_file(_VALID / "import-kind.yml")
    assert spec.sources[0].kind is PatternKind.IMPORT
    assert {p.pattern for p in spec.sources} == {"pickle", "flask.*"}


# --------------------------------------------------------------------------- #
# Structural errors.
# --------------------------------------------------------------------------- #
def test_duplicate_top_level_key_rejected() -> None:
    with pytest.raises(DSLError) as exc:
        parse_spec("id: a\nid: b\nname: n\ncwe: CWE-1\nseverity: low\n")
    assert "duplicate key" in exc.value.message


def test_non_mapping_root_rejected() -> None:
    with pytest.raises(DSLError) as exc:
        parse_spec("- a\n- b\n")
    assert "top level must be a mapping" in exc.value.message


def test_empty_document_rejected() -> None:
    with pytest.raises(DSLError) as exc:
        parse_spec("")
    assert "empty spec" in exc.value.message


def test_invalid_yaml_rejected() -> None:
    with pytest.raises(DSLError) as exc:
        parse_spec("sources: [ unterminated\n")
    assert "not valid YAML" in exc.value.message


def test_yaml_error_does_not_leak() -> None:
    import yaml

    try:
        parse_spec("a: [1, 2\n")
    except DSLError:
        pass
    except yaml.YAMLError as exc:  # pragma: no cover - failure path
        raise AssertionError("raw yaml error leaked") from exc


# --------------------------------------------------------------------------- #
# Error string format + locations.
# --------------------------------------------------------------------------- #
def test_dslerror_str_format() -> None:
    with pytest.raises(DSLError) as exc:
        parse_spec(_spec(severity="nope"), source_path="detectors/x.yml")
    err = exc.value
    assert err.source_path == "detectors/x.yml"
    assert err.spec_id == "python.test.x"
    assert err.field == "severity"
    assert err.line is not None and err.line >= 1
    text = str(err)
    assert "detectors/x.yml:" in text
    assert "[python.test.x]" in text
    assert "severity:" in text


def test_bare_dslerror_still_works() -> None:
    err = DSLError("boom")
    assert "boom" in str(err)
    assert err.spec_id is None


# --------------------------------------------------------------------------- #
# Shape edge cases (node-type mismatches and missing inner keys).
# --------------------------------------------------------------------------- #
def test_sources_must_be_a_list() -> None:
    text = _spec().replace('sources:\n  - { kind: call, pattern: "input" }', "sources: notalist")
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "expected a list" in exc.value.message


def test_pattern_element_must_be_a_mapping() -> None:
    text = _spec().replace('sources:\n  - { kind: call, pattern: "input" }', "sources:\n  - 42")
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "expected a mapping" in exc.value.message


def test_pattern_missing_kind() -> None:
    text = _spec().replace('kind: call, pattern: "input"', 'pattern: "input"')
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "kind" in exc.value.message


def test_pattern_missing_pattern() -> None:
    text = _spec().replace('kind: call, pattern: "input"', "kind: call")
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "pattern" in exc.value.message


def test_non_string_mapping_key_rejected() -> None:
    with pytest.raises(DSLError) as exc:
        parse_spec("1: a\nid: x\n")
    assert "mapping keys must be strings" in exc.value.message


def test_metadata_must_be_a_mapping() -> None:
    text = _spec() + "metadata: notamap\n"
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "mapping" in exc.value.message


def test_when_keyword_empty_rejected() -> None:
    text = _spec().replace(
        'pattern: "os.system"', 'pattern: "subprocess.run", when: { keyword: {} }'
    )
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "keyword" in exc.value.message


def test_when_keyword_bad_identifier_rejected() -> None:
    text = _spec().replace(
        'pattern: "os.system"', 'pattern: "subprocess.run", when: { keyword: { "1bad": 1 } }'
    )
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "identifier" in exc.value.message


def test_flow_missing_to_rejected() -> None:
    text = _with_propagator('kind: call, pattern: "f", flow: { from: any-arg }')
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "to" in exc.value.message


def test_flow_must_be_a_mapping() -> None:
    text = _with_propagator('kind: call, pattern: "f", flow: oops')
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "mapping" in exc.value.message


def test_metadata_yaml_false_and_null_coerced() -> None:
    text = _spec() + "metadata:\n  flag: false\n  empty: null\n"
    spec = parse_spec(text)
    assert spec.metadata["flag"] is False
    assert spec.metadata["empty"] is None


def test_metadata_float_rejected() -> None:
    text = _spec() + "metadata:\n  ratio: 1.5\n"
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert "scalar" in exc.value.message


@pytest.mark.parametrize("value", ["010", "1:30"])
def test_metadata_yaml_int_spelling_raises_dslerror(value: str) -> None:
    # The YAML 1.1 resolver tags spellings like `010` (leading zero) and `1:30`
    # (sexagesimal) as ints, but Python's int(raw, 0) rejects them. The raw
    # ValueError must be turned into a location-aware DSLError, never leak.
    text = _spec() + f"metadata:\n  v: {value}\n"
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert exc.value.field == "metadata"
    assert value in exc.value.message


def test_metadata_self_referential_anchor_raises_dslerror() -> None:
    # A self-referential YAML anchor composes a node that contains itself; naive
    # recursion would loop forever (RecursionError). It must be rejected as a
    # DSLError on the cycle instead.
    text = _spec() + "metadata: &m\n  self: *m\n"
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    assert exc.value.field == "metadata"
    assert "anchor" in exc.value.message


def test_metadata_benign_alias_reuse_still_parses() -> None:
    # A non-cyclic alias reused across sibling branches is legitimate and must
    # not be mistaken for a cycle (path-scoped, not global, visited tracking).
    text = _spec() + "metadata:\n  a: &x\n    k: v\n  b: *x\n"
    spec = parse_spec(text)
    assert dict(spec.metadata["a"]) == {"k": "v"}
    assert dict(spec.metadata["b"]) == {"k": "v"}


def test_error_location_points_at_offending_line() -> None:
    text = _spec() + "bogus: 1\n"
    with pytest.raises(DSLError) as exc:
        parse_spec(text)
    # `bogus:` is the last line of the document.
    assert exc.value.line == len(text.strip().splitlines())


# --------------------------------------------------------------------------- #
# Determinism.
# --------------------------------------------------------------------------- #
def test_determinism_same_text_equal_spec() -> None:
    assert parse_spec(_MINIMAL) == parse_spec(_MINIMAL)


def test_first_error_is_stable() -> None:
    # Two errors present (unknown key AND bad severity); the unknown key appears
    # first in document order, so it must be the reported one every time.
    text = (
        "id: python.test.x\nname: n\ncwe: CWE-1\nseverity: nope\n"
        "languages: [python]\nmessage: m\nbogus: 1\n"
        'sources:\n  - { kind: call, pattern: "input" }\n'
        'sinks:\n  - { kind: call, pattern: "os.system" }\n'
    )
    first = parse_spec_error(text)
    second = parse_spec_error(text)
    assert first == second == "bogus"


def parse_spec_error(text: str) -> str | None:
    try:
        parse_spec(text)
    except DSLError as exc:
        return exc.field
    return None


# --------------------------------------------------------------------------- #
# Fixture corpus sweep (data-driven, mirrors the fixtures lint-exclude).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", sorted(_INVALID.glob("*.yml")), ids=lambda p: p.name)
def test_invalid_fixture_raises_dslerror(path: Path) -> None:
    with pytest.raises(DSLError):
        load_spec_file(path)


@pytest.mark.parametrize("path", sorted(_VALID.glob("*.yml")), ids=lambda p: p.name)
def test_valid_fixture_parses(path: Path) -> None:
    spec = load_spec_file(path)
    assert spec.id
    assert spec.sources
    assert spec.sinks
