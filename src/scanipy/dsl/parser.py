# SPDX-License-Identifier: Apache-2.0
"""Parse + validate taint-DSL YAML into a :class:`~scanipy.dsl.spec.DetectorSpec`.

This is the single entry point that turns a detector's YAML text into a
validated, frozen :class:`DetectorSpec` — the one source of all detection logic
(principle P4). Every field shape, enum, and pattern/flow grammar is validated;
any unknown key or kind is rejected; and every failure raises a location-aware
:class:`DSLError` that names the spec id, the offending field, and a source
line/column.

The canonical, field-by-field schema this enforces lives in
``docs/dsl-reference.md``. Parsing uses only the stdlib plus the already-present
``pyyaml`` (no new runtime dependency).

Implementation notes
--------------------
We do **not** call :func:`yaml.safe_load` (it discards positions). Instead we
compose the YAML node tree once with :func:`yaml.compose` and walk it, so every
value carries its source ``start_mark`` for precise error reporting. Marks are
0-based for both line and column; human output adds 1 to the line.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from scanipy.dsl.patterns import Flow, Pattern, PatternKind, Propagator
from scanipy.dsl.spec import DetectorSpec
from scanipy.models import Severity

# --------------------------------------------------------------------------- #
# Grammar constants — centralized so a future DSL extension is one local change.
# --------------------------------------------------------------------------- #
_REQUIRED_TOP = ("id", "name", "cwe", "severity", "languages", "message", "sources", "sinks")
_OPTIONAL_TOP = ("sanitizers", "propagators", "metadata")
_ALLOWED_TOP = frozenset(_REQUIRED_TOP) | frozenset(_OPTIONAL_TOP)

_PATTERN_KEYS = frozenset({"kind", "pattern", "args", "when"})
_PROP_KEYS = frozenset({"kind", "pattern", "args", "when", "flow"})

_PLAIN_FLOW_TOKENS = frozenset({"any-arg", "self", "return"})
_SUPPORTED_LANGUAGES = ("python",)
_SEVERITY_VALUES = ("low", "medium", "high", "critical")

_DOTTED_RE = re.compile(r"^(\*|[A-Za-z_][A-Za-z0-9_]*)(\.(\*|[A-Za-z_][A-Za-z0-9_]*))*$")
_CWE_RE = re.compile(r"^CWE-\d+$")
_ARG_FLOW_RE = re.compile(r"^arg:\d+$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# YAML 1.1 scalar tags we accept for typed scalars. Any other tag (e.g. float)
# is outside the DSL scalar vocabulary and is rejected.
_TAG_STR = "tag:yaml.org,2002:str"
_TAG_BOOL = "tag:yaml.org,2002:bool"
_TAG_INT = "tag:yaml.org,2002:int"
_TAG_NULL = "tag:yaml.org,2002:null"

# YAML 1.1 truthy/falsy spellings (resolved to the bool tag by the SafeLoader).
_YAML_TRUE = frozenset({"yes", "true", "on", "y"})
_YAML_FALSE = frozenset({"no", "false", "off", "n"})


class DSLError(ValueError):
    """A detector spec is not valid taint-DSL.

    Carries enough context to point a human (and a test) at the exact problem:
    the spec ``id``, the offending ``field`` path, the ``source_path``, and a
    1-based ``line`` / 0-based ``column``. ``str(self)`` is a single
    deterministic line of the form
    ``path:line:col: [spec_id] field: message`` (principle P3).
    """

    def __init__(
        self,
        message: str,
        *,
        spec_id: str | None = None,
        field: str | None = None,
        source_path: str | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        self.message = message
        self.spec_id = spec_id
        self.field = field
        self.source_path = source_path
        self.line = line
        self.column = column
        loc_path = source_path or "<spec>"
        prefix = f"{loc_path}:{line}:{column}: [{spec_id or '?'}]"
        field_part = f" {field}:" if field else ""
        super().__init__(f"{prefix}{field_part} {message}")


@dataclass(frozen=True)
class _Ctx:
    """Threaded parse context so every error carries the spec id + file."""

    spec_id: str | None
    source_path: str | None


def _err(
    message: str,
    *,
    ctx: _Ctx,
    node: Node | None = None,
    field: str | None = None,
) -> DSLError:
    """Build a :class:`DSLError` from a node mark and the threaded context.

    Every raise routes through here so the formatting stays uniform (P3). When a
    ``node`` is given, its ``start_mark`` supplies the location (line+1 to make it
    1-based, column kept 0-based); otherwise we fall back to (1, 0).
    """
    if node is not None and node.start_mark is not None:
        line = node.start_mark.line + 1
        column = node.start_mark.column
    else:
        line = 1
        column = 0
    return DSLError(
        message,
        spec_id=ctx.spec_id,
        field=field,
        source_path=ctx.source_path,
        line=line,
        column=column,
    )


# --------------------------------------------------------------------------- #
# Node helpers — walk the composed tree, never lose positions.
# --------------------------------------------------------------------------- #
def _as_mapping(node: Node, *, ctx: _Ctx, field: str | None = None) -> dict[str, Node]:
    """Convert a ``MappingNode`` to an ordered ``{str: child-node}`` dict.

    Rejects non-mapping nodes, non-string keys, and duplicate keys (each with the
    most specific available mark). Returns child *nodes* (not plain values) so
    nested validators keep precise locations.
    """
    if not isinstance(node, MappingNode):
        raise _err("expected a mapping", ctx=ctx, node=node, field=field)
    result: dict[str, Node] = {}
    for key_node, value_node in node.value:
        if not isinstance(key_node, ScalarNode) or key_node.tag != _TAG_STR:
            raise _err("mapping keys must be strings", ctx=ctx, node=key_node, field=field)
        key = key_node.value
        if key in result:
            raise _err(f"duplicate key {key!r}", ctx=ctx, node=key_node, field=field)
        result[key] = value_node
    return result


def _as_list(node: Node, *, ctx: _Ctx, field: str | None = None) -> list[Node]:
    """Convert a ``SequenceNode`` to a list of child nodes."""
    if not isinstance(node, SequenceNode):
        raise _err("expected a list", ctx=ctx, node=node, field=field)
    return list(node.value)


def _scalar_value(node: Node, *, ctx: _Ctx, field: str | None = None) -> str | bool | int | None:
    """Convert a scalar node to a typed Python value via its resolved tag.

    We switch on the tag (not Python's loose truthiness) so e.g. ``severity: yes``
    becomes a ``bool`` — and is therefore rejected where a ``str`` is required —
    rather than silently passing as the string ``"yes"``.
    """
    if not isinstance(node, ScalarNode):
        raise _err("expected a scalar value", ctx=ctx, node=node, field=field)
    tag = node.tag
    raw: str = node.value
    if tag == _TAG_STR:
        return raw
    if tag == _TAG_BOOL:
        lowered = raw.lower()
        if lowered in _YAML_TRUE:
            return True
        if lowered in _YAML_FALSE:
            return False
        raise _err(f"invalid boolean {raw!r}", ctx=ctx, node=node, field=field)
    if tag == _TAG_INT:
        return int(raw, 0)
    if tag == _TAG_NULL:
        return None
    # floats and any other tag are not part of the scalar vocabulary.
    raise _err(f"unsupported scalar type {tag!r}", ctx=ctx, node=node, field=field)


def _require_str(node: Node, *, ctx: _Ctx, field: str) -> str:
    """Return a non-empty string scalar or raise with the field name."""
    if not isinstance(node, ScalarNode) or node.tag != _TAG_STR:
        raise _err(f"expected a string for {field!r}", ctx=ctx, node=node, field=field)
    value: str = node.value
    if not value.strip():
        raise _err(f"{field!r} must not be empty", ctx=ctx, node=node, field=field)
    return value


# --------------------------------------------------------------------------- #
# Metadata — free-form, but only well-typed scalars/lists/maps.
# --------------------------------------------------------------------------- #
def _build_metadata(node: Node, *, ctx: _Ctx) -> object:
    """Recursively build a metadata subtree, preserving document order.

    Mappings become ``MappingProxyType`` (read-only), sequences become tuples,
    and scalars are typed via :func:`_scalar_value`. Order is never sorted so the
    value is stable for future fingerprinting.
    """
    if isinstance(node, MappingNode):
        mapping = _as_mapping(node, ctx=ctx, field="metadata")
        return MappingProxyType(
            {key: _build_metadata(child, ctx=ctx) for key, child in mapping.items()}
        )
    if isinstance(node, SequenceNode):
        return tuple(_build_metadata(child, ctx=ctx) for child in node.value)
    return _scalar_value(node, ctx=ctx, field="metadata")


# --------------------------------------------------------------------------- #
# Pattern parsing.
# --------------------------------------------------------------------------- #
def _validate_pattern_string(
    value: str, kind: PatternKind, *, ctx: _Ctx, node: Node, field: str
) -> None:
    """Validate a pattern's dotted/wildcard *shape* (not its engine semantics).

    All kinds share the dotted grammar: ``.``-separated segments, each either a
    Python identifier or ``*``. This rejects empty/leading/trailing/double dots,
    spaces, parentheses, and brackets. ``parameter`` (a bare name or scoped
    selector) and ``import`` (a module path, optionally ending ``*``) both fit the
    same grammar; only shape is checked here.
    """
    if not value:
        raise _err("pattern must not be empty", ctx=ctx, node=node, field=field)
    if not _DOTTED_RE.match(value):
        raise _err(
            f"invalid pattern {value!r}: expected dotted segments of identifiers or '*'",
            ctx=ctx,
            node=node,
            field=field,
        )


def _parse_args(node: Node, *, ctx: _Ctx, field: str) -> tuple[int, ...]:
    """Parse an ``args`` list into a sorted, de-duplicated tuple of indices."""
    elements = _as_list(node, ctx=ctx, field=field)
    if not elements:
        raise _err("'args' must list at least one index", ctx=ctx, node=node, field=field)
    indices: set[int] = set()
    for element in elements:
        if not isinstance(element, ScalarNode) or element.tag != _TAG_INT:
            raise _err("'args' indices must be integers", ctx=ctx, node=element, field=field)
        index = int(element.value, 0)
        if index < 0:
            raise _err("'args' indices must be non-negative", ctx=ctx, node=element, field=field)
        indices.add(index)
    return tuple(sorted(indices))


def _parse_when(node: Node, *, ctx: _Ctx, field: str) -> Mapping[str, object]:
    """Parse a ``when`` constraint: exactly ``{keyword: {name: scalar}}``.

    The nested shape is preserved exactly as the engine reads it
    (``when:{keyword:{shell:true}}`` -> ``{"keyword": {"shell": True}}``); scalar
    types are kept distinct so ``shell: true`` (bool) and ``shell: 'true'`` (str)
    stay distinguishable.
    """
    mapping = _as_mapping(node, ctx=ctx, field=field)
    for key in mapping:
        if key != "keyword":
            raise _err(
                f"unknown 'when' condition {key!r}; v1 supports: keyword",
                ctx=ctx,
                node=node,
                field=field,
            )
    keyword_node = mapping.get("keyword")
    if keyword_node is None:
        raise _err("'when' requires a 'keyword' condition", ctx=ctx, node=node, field=field)
    keyword_map = _as_mapping(keyword_node, ctx=ctx, field=f"{field}.keyword")
    if not keyword_map:
        raise _err("'when.keyword' must not be empty", ctx=ctx, node=keyword_node, field=field)
    resolved: dict[str, object] = {}
    for name, value_node in keyword_map.items():
        if not _IDENTIFIER_RE.match(name):
            raise _err(
                f"'when.keyword' name {name!r} must be a valid identifier",
                ctx=ctx,
                node=value_node,
                field=field,
            )
        if not isinstance(value_node, ScalarNode):
            raise _err(
                "'when.keyword' values must be scalars",
                ctx=ctx,
                node=value_node,
                field=field,
            )
        resolved[name] = _scalar_value(value_node, ctx=ctx, field=f"{field}.keyword.{name}")
    return MappingProxyType({"keyword": MappingProxyType(resolved)})


def _parse_pattern(
    node: Node,
    field: str,
    idx: int,
    *,
    ctx: _Ctx,
    allowed_keys: frozenset[str] = _PATTERN_KEYS,
) -> Pattern:
    """Parse one pattern mapping into a frozen :class:`Pattern`.

    ``allowed_keys`` widens the accepted key set for propagators (which add a
    ``flow`` key on the same mapping); the pattern fields themselves are still
    drawn only from ``kind``/``pattern``/``args``/``when``.
    """
    where = f"{field}[{idx}]"
    mapping = _as_mapping(node, ctx=ctx, field=where)

    for key in mapping:
        if key not in allowed_keys:
            raise _err(f"unknown pattern field {key!r} in {where}", ctx=ctx, node=node, field=where)

    if "kind" not in mapping:
        raise _err("missing pattern field 'kind'", ctx=ctx, node=node, field=where)
    kind_value = _require_str(mapping["kind"], ctx=ctx, field=f"{where}.kind")
    try:
        kind = PatternKind(kind_value)
    except ValueError as exc:
        raise _err(
            f"unknown pattern kind {kind_value!r}; valid: call, attribute, parameter, import",
            ctx=ctx,
            node=mapping["kind"],
            field=f"{where}.kind",
        ) from exc

    if "pattern" not in mapping:
        raise _err("missing pattern field 'pattern'", ctx=ctx, node=node, field=where)
    pattern_value = _require_str(mapping["pattern"], ctx=ctx, field=f"{where}.pattern")
    _validate_pattern_string(
        pattern_value, kind, ctx=ctx, node=mapping["pattern"], field=f"{where}.pattern"
    )

    args: tuple[int, ...] | None = None
    if "args" in mapping:
        if kind is not PatternKind.CALL:
            raise _err(
                "'args' is only valid on kind: call",
                ctx=ctx,
                node=mapping["args"],
                field=f"{where}.args",
            )
        args = _parse_args(mapping["args"], ctx=ctx, field=f"{where}.args")

    when: Mapping[str, object] | None = None
    if "when" in mapping:
        if kind is not PatternKind.CALL:
            raise _err(
                "'when' is only valid on kind: call",
                ctx=ctx,
                node=mapping["when"],
                field=f"{where}.when",
            )
        when = _parse_when(mapping["when"], ctx=ctx, field=f"{where}.when")

    return Pattern(kind=kind, pattern=pattern_value, args=args, when=when)


def _validate_flow_token(value: str, *, ctx: _Ctx, node: Node, field: str) -> str:
    """Validate a flow token: ``any-arg`` | ``self`` | ``return`` | ``arg:N``."""
    if value in _PLAIN_FLOW_TOKENS or _ARG_FLOW_RE.match(value):
        return value
    raise _err(
        f"invalid flow token {value!r}; valid: any-arg, arg:N, self, return",
        ctx=ctx,
        node=node,
        field=field,
    )


def _parse_propagator(node: Node, idx: int, *, ctx: _Ctx) -> Propagator:
    """Parse one propagator mapping into a frozen :class:`Propagator`."""
    where = f"propagators[{idx}]"
    mapping = _as_mapping(node, ctx=ctx, field=where)

    if "flow" not in mapping:
        raise _err("propagators require a 'flow'", ctx=ctx, node=node, field=where)

    pattern = _parse_pattern(node, "propagators", idx, ctx=ctx, allowed_keys=_PROP_KEYS)
    if pattern.kind is not PatternKind.CALL:
        raise _err(
            "propagators must be kind: call",
            ctx=ctx,
            node=mapping["kind"],
            field=f"{where}.kind",
        )

    flow_field = f"{where}.flow"
    flow_map = _as_mapping(mapping["flow"], ctx=ctx, field=flow_field)
    for key in flow_map:
        if key not in ("from", "to"):
            raise _err(
                f"unknown flow field {key!r}; expected exactly 'from' and 'to'",
                ctx=ctx,
                node=mapping["flow"],
                field=flow_field,
            )
    if "from" not in flow_map:
        raise _err("flow requires 'from'", ctx=ctx, node=mapping["flow"], field=flow_field)
    if "to" not in flow_map:
        raise _err("flow requires 'to'", ctx=ctx, node=mapping["flow"], field=flow_field)

    from_value = _require_str(flow_map["from"], ctx=ctx, field=f"{flow_field}.from")
    to_value = _require_str(flow_map["to"], ctx=ctx, field=f"{flow_field}.to")
    _validate_flow_token(from_value, ctx=ctx, node=flow_map["from"], field=f"{flow_field}.from")
    _validate_flow_token(to_value, ctx=ctx, node=flow_map["to"], field=f"{flow_field}.to")

    return Propagator(pattern=pattern, flow=Flow(from_=from_value, to=to_value))


# --------------------------------------------------------------------------- #
# Top-level field parsing.
# --------------------------------------------------------------------------- #
def _parse_pattern_list(
    mapping: dict[str, Node], field: str, *, ctx: _Ctx, require_nonempty: bool
) -> tuple[Pattern, ...]:
    """Parse a list of patterns under ``field`` (sources/sinks/sanitizers)."""
    node = mapping[field]
    elements = _as_list(node, ctx=ctx, field=field)
    if require_nonempty and not elements:
        raise _err(f"{field!r} must have at least one pattern", ctx=ctx, node=node, field=field)
    return tuple(
        _parse_pattern(element, field, idx, ctx=ctx) for idx, element in enumerate(elements)
    )


def parse_spec(text: str, *, source_path: str | None = None) -> DetectorSpec:
    """Parse taint-DSL YAML text into a frozen :class:`DetectorSpec`.

    Raises :class:`DSLError` on anything that is syntactically valid YAML but not
    valid taint-DSL (and also on invalid YAML — a raw ``yaml`` exception never
    escapes). The validation is exhaustive: unknown keys, bad enums, malformed
    patterns/flows, and empty required lists are all rejected with a precise,
    location-aware error.
    """
    boot_ctx = _Ctx(spec_id=None, source_path=source_path)

    # Phase 0 — YAML load with location tracking.
    try:
        root = yaml.compose(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark is not None else 1
        column = mark.column if mark is not None else 0
        problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        raise DSLError(
            f"not valid YAML: {problem}",
            source_path=source_path,
            line=line,
            column=column,
        ) from exc

    if root is None:
        raise DSLError("empty spec", source_path=source_path, line=1, column=0)
    if not isinstance(root, MappingNode):
        raise _err("top level must be a mapping", ctx=boot_ctx, node=root)

    mapping = _as_mapping(root, ctx=boot_ctx)

    # Phase 1 — top-level field validation. Parse id first so every later error
    # carries the spec id.
    if "id" not in mapping:
        raise _err("missing required field 'id'", ctx=boot_ctx, node=root, field="id")
    spec_id = _require_str(mapping["id"], ctx=boot_ctx, field="id")
    ctx = _Ctx(spec_id=spec_id, source_path=source_path)

    # Reject unknown top-level keys in document order (first offending wins).
    for key, key_node in mapping.items():
        if key not in _ALLOWED_TOP:
            raise _err(f"unknown top-level field {key!r}", ctx=ctx, node=key_node, field=key)

    # Missing required keys.
    for key in _REQUIRED_TOP:
        if key not in mapping:
            raise _err(f"missing required field {key!r}", ctx=ctx, node=root, field=key)

    name = _require_str(mapping["name"], ctx=ctx, field="name")
    message = _require_str(mapping["message"], ctx=ctx, field="message")

    cwe = _require_str(mapping["cwe"], ctx=ctx, field="cwe")
    if not _CWE_RE.match(cwe):
        raise _err(
            f"cwe must look like 'CWE-79', got {cwe!r}", ctx=ctx, node=mapping["cwe"], field="cwe"
        )

    severity_value = _require_str(mapping["severity"], ctx=ctx, field="severity")
    if severity_value not in _SEVERITY_VALUES:
        raise _err(
            f"severity must be one of low|medium|high|critical, got {severity_value!r}",
            ctx=ctx,
            node=mapping["severity"],
            field="severity",
        )
    severity = Severity.from_str(severity_value)

    languages = _parse_languages(mapping["languages"], ctx=ctx)

    metadata: Mapping[str, object] = MappingProxyType({})
    if "metadata" in mapping:
        built = _build_metadata(mapping["metadata"], ctx=ctx)
        if not isinstance(built, MappingProxyType):
            raise _err(
                "metadata must be a mapping", ctx=ctx, node=mapping["metadata"], field="metadata"
            )
        metadata = built

    # Phase 2 — pattern lists.
    sources = _parse_pattern_list(mapping, "sources", ctx=ctx, require_nonempty=True)
    sinks = _parse_pattern_list(mapping, "sinks", ctx=ctx, require_nonempty=True)
    sanitizers: tuple[Pattern, ...] = ()
    if "sanitizers" in mapping:
        sanitizers = _parse_pattern_list(mapping, "sanitizers", ctx=ctx, require_nonempty=False)
    propagators: tuple[Propagator, ...] = ()
    if "propagators" in mapping:
        prop_node = mapping["propagators"]
        prop_elements = _as_list(prop_node, ctx=ctx, field="propagators")
        propagators = tuple(
            _parse_propagator(element, idx, ctx=ctx) for idx, element in enumerate(prop_elements)
        )

    # Phase 3 — assemble + return.
    return DetectorSpec(
        id=spec_id,
        name=name,
        cwe=cwe,
        severity=severity,
        languages=languages,
        message=message,
        sources=sources,
        sinks=sinks,
        sanitizers=sanitizers,
        propagators=propagators,
        metadata=metadata,
    )


def _parse_languages(node: Node, *, ctx: _Ctx) -> tuple[str, ...]:
    """Parse ``languages``: a non-empty list of ``python`` (v1 scope, P7)."""
    elements = _as_list(node, ctx=ctx, field="languages")
    if not elements:
        raise _err(
            "'languages' must have at least one entry", ctx=ctx, node=node, field="languages"
        )
    languages: list[str] = []
    for element in elements:
        value = _require_str(element, ctx=ctx, field="languages")
        if value not in _SUPPORTED_LANGUAGES:
            raise _err(
                f"unsupported language {value!r}; v1 supports: python",
                ctx=ctx,
                node=element,
                field="languages",
            )
        languages.append(value)
    return tuple(languages)


def load_spec_file(path: str | Path) -> DetectorSpec:
    """Read and parse a detector spec file (UTF-8)."""
    p = Path(path)
    return parse_spec(p.read_text(encoding="utf-8"), source_path=str(p))
