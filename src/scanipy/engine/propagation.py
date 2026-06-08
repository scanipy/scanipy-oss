# SPDX-License-Identifier: Apache-2.0
"""Generic, detector-agnostic taint propagation (``ENGINE_5`` / ``ENGINE_8``).

:func:`expr_taint` computes the set of :class:`~scanipy.engine.taint_state.TaintLabel`
values that flow *out* of evaluating one IR expression in a given
:class:`~scanipy.engine.taint_state.TaintEnv`. It implements the engine's built-in
propagation rules — applied to **every** spec equally (principle P4) — plus the
hooks the rest of the engine drives:

* **Sources.** A sub-expression matching any spec's ``source`` pattern introduces
  a fresh label for that spec (one label per matching ``spec_id``), so a source
  nested directly inside a sink (``os.system(input())``) still seeds taint.
* **String-shaped propagation.** ``+`` / ``%`` / ``*`` on operands, f-strings,
  containers, comprehensions, boolean / conditional value-unions, and built-in
  ``str`` methods carry taint without any per-library rule.
* **Calls.** A sanitizer cleans its spec from the return; spec ``propagators``,
  built-in ``str``-method defaults, in-file :class:`FunctionSummary` application,
  and a conservative external-callee fallback (``any-arg -> return``) all move
  taint, appending a PROPAGATOR witness step at genuine call hops.

The module never branches on a CWE or library name; all knowledge comes from the
:class:`~scanipy.dsl.DetectorSpec` pack carried in the :class:`PropagationContext`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from scanipy.dsl import DetectorSpec, Flow, Pattern, PatternKind
from scanipy.engine.matcher import match
from scanipy.engine.taint_state import (
    AccessPath,
    AccessStep,
    TaintEnv,
    TaintLabel,
    TaintProvenance,
    with_replaced_chain,
)
from scanipy.engine.witness import make_step
from scanipy.ir import (
    Expr,
    IRAttribute,
    IRBinOp,
    IRBoolOp,
    IRCall,
    IRComprehension,
    IRContainer,
    IRFormattedValue,
    IRIfExp,
    IRJoinedStr,
    IRLiteral,
    IRName,
    IRStarred,
    IRSubscript,
)
from scanipy.models import Location, WitnessRole, WitnessStep

# Built-in string methods that carry taint receiver/any-arg -> return. Kept as a
# generic default (P4): these are language features, not per-detector knowledge.
_STR_METHODS = frozenset(
    {
        "capitalize",
        "casefold",
        "center",
        "encode",
        "expandtabs",
        "format",
        "format_map",
        "join",
        "ljust",
        "lower",
        "lstrip",
        "removeprefix",
        "removesuffix",
        "replace",
        "rjust",
        "rstrip",
        "strip",
        "swapcase",
        "title",
        "translate",
        "upper",
        "zfill",
    }
)

# String binary operators that carry taint from either operand into the result.
_STRING_BINOPS = frozenset({"+", "%", "*"})


@dataclass(frozen=True)
class SummaryFlow:
    """One transfer fact from a callee summary, with a spliceable fragment.

    ``src_kind`` / ``dst_kind`` are flow-vocabulary roles (``"param"``, ``"self"``,
    ``"return"``, ``"sink"``, ``"source"``); ``src_index`` is the parameter index
    for ``"param"``. ``spec_id`` scopes ``source``/``sink`` ends. ``fragment`` is
    the witness sub-trace spliced into the caller at the call site.
    """

    src_kind: str
    src_index: int | None
    dst_kind: str
    spec_id: str | None
    fragment: tuple[WitnessStep, ...]
    sink_location: Location | None = None


@dataclass(frozen=True)
class FunctionSummary:
    """A callee's transfer-input/transfer-output (TITO) summary (sorted flows)."""

    qualname: str
    flows: tuple[SummaryFlow, ...]


@dataclass
class PropagationContext:
    """Shared, read-only inputs threaded through propagation.

    ``summaries`` maps an in-file function *qualname* to its :class:`FunctionSummary`.
    ``callee_resolver`` maps a call's ``callee_path`` (e.g. ``"obj.run"``) to the
    in-file qualname it resolves to (``"run"``), mirroring the call-graph resolver,
    so a method/aliased call applies the right summary. ``findings`` collects the
    interprocedural sink hits discovered while applying summaries at call sites.
    """

    specs: Sequence[DetectorSpec]
    summaries: Mapping[str, FunctionSummary] = field(default_factory=dict)
    callee_resolver: Mapping[str, str] = field(default_factory=dict)
    findings: list[InterprocSink] = field(default_factory=list)

    def resolve_summary(self, callee_path: str | None) -> FunctionSummary | None:
        """Return the summary for a call's ``callee_path``, resolving aliases."""
        if callee_path is None:
            return None
        direct = self.summaries.get(callee_path)
        if direct is not None:
            return direct
        qualname = self.callee_resolver.get(callee_path)
        if qualname is not None:
            return self.summaries.get(qualname)
        return None


@dataclass(frozen=True)
class InterprocSink:
    """An interprocedural sink hit found while applying a callee summary."""

    spec: DetectorSpec
    sink_location: Location
    witness: tuple[WitnessStep, ...]


# ---------------------------------------------------------------------------
# Access-path derivation
# ---------------------------------------------------------------------------


def access_path_of(expr: Expr) -> AccessPath | None:
    """Reduce a readable expression to a bounded :class:`AccessPath`, or ``None``.

    Handles ``name`` / ``name.attr`` / ``name[const]`` chains; dynamic subscripts
    and call-rooted chains over-approximate to the base or yield ``None`` so the
    engine never tracks an unbounded or dynamic key.
    """
    if isinstance(expr, IRName):
        return AccessPath(base=expr.name)
    if isinstance(expr, IRAttribute):
        base = access_path_of(expr.value)
        if base is None:
            return None
        return base.extend(AccessStep(kind="attr", value=expr.attr))
    if isinstance(expr, IRSubscript):
        base = access_path_of(expr.value)
        if base is None:
            return None
        if expr.is_const_index:
            return base.extend(AccessStep(kind="index", value=repr(expr.const_index)))
        # Dynamic index: taint the whole container (collapse to its base path).
        return base
    if isinstance(expr, IRStarred):
        return access_path_of(expr.value)
    return None


# ---------------------------------------------------------------------------
# Source detection
# ---------------------------------------------------------------------------


def _source_labels_for(expr: Expr, specs: Sequence[DetectorSpec]) -> frozenset[TaintLabel]:
    """Fresh labels for every spec whose ``source`` pattern matches ``expr``.

    A single site may seed several specs (e.g. ``input()`` feeds both os-command
    and sql); each gets its own label with a SOURCE-rooted provenance chain.
    """
    out: set[TaintLabel] = set()
    for spec in sorted(specs, key=lambda s: s.id):
        for pattern in spec.sources:
            if _source_matches(pattern, expr):
                step = make_step(
                    WitnessRole.SOURCE,
                    expr.location,
                    f"source {pattern.pattern}",
                )
                out.add(
                    TaintLabel(
                        spec_id=spec.id,
                        provenance=TaintProvenance(spec_id=spec.id, chain=(step,)),
                    )
                )
                break  # one label per spec is enough (best provenance kept later)
    return frozenset(out)


def _source_matches(pattern: Pattern, expr: Expr) -> bool:
    """True if a source ``pattern`` matches the readable expression ``expr``."""
    if pattern.kind is PatternKind.CALL:
        return isinstance(expr, IRCall) and match(pattern, expr) is not None
    if pattern.kind is PatternKind.ATTRIBUTE:
        return isinstance(expr, IRAttribute) and match(pattern, expr) is not None
    # parameter/import sources are not seeded at expression sites in v1 (P7).
    return False


# ---------------------------------------------------------------------------
# expr_taint
# ---------------------------------------------------------------------------


def expr_taint(expr: Expr, env: TaintEnv, ctx: PropagationContext) -> frozenset[TaintLabel]:
    """Labels flowing out of evaluating ``expr`` in ``env`` (the core transfer)."""
    labels = _source_labels_for(expr, ctx.specs)

    if isinstance(expr, IRName | IRAttribute | IRSubscript):
        ap = access_path_of(expr)
        if ap is not None:
            labels |= env.get(ap)
        if isinstance(expr, IRSubscript):
            labels |= expr_taint(expr.index, env, ctx)
        return _merge(labels)

    if isinstance(expr, IRLiteral):
        return _merge(labels)

    if isinstance(expr, IRBinOp):
        if expr.op in _STRING_BINOPS:
            labels |= expr_taint(expr.left, env, ctx)
            labels |= expr_taint(expr.right, env, ctx)
        return _merge(labels)

    if isinstance(expr, IRBoolOp):
        for value in expr.values:
            labels |= expr_taint(value, env, ctx)
        return _merge(labels)

    if isinstance(expr, IRIfExp):
        # Value-union of the two arms; the test is a control flow, not data (P7).
        labels |= expr_taint(expr.body, env, ctx)
        labels |= expr_taint(expr.orelse, env, ctx)
        return _merge(labels)

    if isinstance(expr, IRJoinedStr):
        for value in expr.values:
            labels |= expr_taint(value, env, ctx)
        return _merge(labels)

    if isinstance(expr, IRFormattedValue):
        labels |= expr_taint(expr.value, env, ctx)
        return _merge(labels)

    if isinstance(expr, IRContainer):
        for element in expr.elements:
            labels |= expr_taint(element, env, ctx)
        for key in expr.keys:
            if key is not None:
                labels |= expr_taint(key, env, ctx)
        return _merge(labels)

    if isinstance(expr, IRComprehension):
        labels |= expr_taint(expr.element, env, ctx)
        if expr.value is not None:
            labels |= expr_taint(expr.value, env, ctx)
        for iterable in expr.iterables:
            labels |= expr_taint(iterable, env, ctx)
        return _merge(labels)

    if isinstance(expr, IRStarred):
        labels |= expr_taint(expr.value, env, ctx)
        return _merge(labels)

    if isinstance(expr, IRCall):
        labels |= _call_taint(expr, env, ctx)
        return _merge(labels)

    return _merge(labels)


# ---------------------------------------------------------------------------
# Call handling
# ---------------------------------------------------------------------------


def _call_taint(call: IRCall, env: TaintEnv, ctx: PropagationContext) -> frozenset[TaintLabel]:
    """Compute the labels a call returns (sanitize / propagate / summarize)."""
    arg_labels = [expr_taint(arg, env, ctx) for arg in call.args]
    kw_labels = [expr_taint(kw.value, env, ctx) for kw in call.kwargs]
    receiver_labels = (
        expr_taint(call.receiver, env, ctx) if call.receiver is not None else frozenset()
    )

    incoming: set[TaintLabel] = set()
    for group in arg_labels:
        incoming |= group
    for group in kw_labels:
        incoming |= group
    incoming |= receiver_labels

    # Which specs sanitize at this call? Their taint is cleaned from the return.
    sanitized_specs = _sanitized_specs(call, ctx.specs)

    out: set[TaintLabel] = set()

    # Spec-declared propagators move taint per their Flow.
    out |= _apply_spec_propagators(call, arg_labels, receiver_labels, ctx)

    # In-file function summary (interprocedural return + sink emission).
    out |= _apply_summary(call, arg_labels, receiver_labels, ctx)

    # Built-in str-method default: tainted receiver/args flow to the return.
    if _is_str_method(call):
        out |= incoming

    # External / unknown callee fallback: pass taint through (any-arg -> return).
    if not _is_known_callee(call, ctx) and not _is_str_method(call):
        out |= incoming

    # Drop labels for specs sanitized at this call (one-sided return cleaning).
    out = {label for label in out if label.spec_id not in sanitized_specs}
    return frozenset(out)


def _is_str_method(call: IRCall) -> bool:
    """True if the call is a known taint-carrying ``str`` method (``x.strip()``)."""
    if call.receiver is None or call.callee_path is None:
        return False
    last = call.callee_path.rsplit(".", 1)[-1]
    return last in _STR_METHODS


def _is_known_callee(call: IRCall, ctx: PropagationContext) -> bool:
    """True if the call resolves to a spec propagator or an in-file summary.

    A "known" callee has explicit propagation, so the conservative pass-through
    fallback is suppressed for it (avoids double-counting / over-tainting).
    """
    if ctx.resolve_summary(call.callee_path) is not None:
        return True
    for spec in ctx.specs:
        for prop in spec.propagators:
            if match(prop.pattern, call) is not None:
                return True
        for sanitizer in spec.sanitizers:
            if match(sanitizer, call) is not None:
                return True
    return False


def _sanitized_specs(call: IRCall, specs: Sequence[DetectorSpec]) -> frozenset[str]:
    """Spec ids whose ``sanitizer`` pattern matches this call (return cleaning)."""
    out: set[str] = set()
    for spec in specs:
        for sanitizer in spec.sanitizers:
            if match(sanitizer, call) is not None:
                out.add(spec.id)
                break
    return frozenset(out)


def _apply_spec_propagators(
    call: IRCall,
    arg_labels: list[frozenset[TaintLabel]],
    receiver_labels: frozenset[TaintLabel],
    ctx: PropagationContext,
) -> frozenset[TaintLabel]:
    """Move taint per each matching spec ``propagator``'s :class:`Flow`."""
    out: set[TaintLabel] = set()
    for spec in sorted(ctx.specs, key=lambda s: s.id):
        for prop in spec.propagators:
            result = match(prop.pattern, call)
            if result is None:
                continue
            if prop.flow.to != "return":
                continue  # v1 propagators only feed the return value
            sources = _flow_source_labels(prop.flow, arg_labels, receiver_labels)
            out |= sources
    return frozenset(out)


_FLOW_ANY_ARG = "any-arg"
_FLOW_SELF = "self"
_FLOW_ARG_PREFIX = "arg:"


def _flow_source_labels(
    flow: Flow,
    arg_labels: list[frozenset[TaintLabel]],
    receiver_labels: frozenset[TaintLabel],
) -> frozenset[TaintLabel]:
    """Resolve a flow ``from`` token to the labels at that source position."""
    out: set[TaintLabel] = set()
    if flow.from_ == _FLOW_ANY_ARG:
        for group in arg_labels:
            out |= group
    elif flow.from_ == _FLOW_SELF:
        out |= receiver_labels
    elif flow.from_.startswith(_FLOW_ARG_PREFIX):
        try:
            index = int(flow.from_[len(_FLOW_ARG_PREFIX) :])
        except ValueError:
            return frozenset()
        if 0 <= index < len(arg_labels):
            out |= arg_labels[index]
    return frozenset(out)


def _apply_summary(
    call: IRCall,
    arg_labels: list[frozenset[TaintLabel]],
    receiver_labels: frozenset[TaintLabel],
    ctx: PropagationContext,
) -> frozenset[TaintLabel]:
    """Apply an in-file callee summary: return labels + interproc sink findings."""
    summary = ctx.resolve_summary(call.callee_path)
    if summary is None:
        return frozenset()

    out: set[TaintLabel] = set()
    call_step = make_step(WitnessRole.PROPAGATOR, call.location, f"call {call.callee_path}")
    for flow in summary.flows:
        incoming = _summary_inputs(flow, arg_labels, receiver_labels)
        if flow.src_kind == "source":
            # A callee-internal source reaching the callee's return unconditionally
            # introduces taint for its spec in the caller. (An in-body source that
            # reaches an in-body sink is emitted intraprocedurally, not summarized.)
            if flow.dst_kind == "return" and flow.spec_id is not None:
                base = make_step(WitnessRole.PROPAGATOR, call.location, f"call {call.callee_path}")
                chain = (base, *flow.fragment)
                out.add(
                    TaintLabel(
                        spec_id=flow.spec_id,
                        provenance=TaintProvenance(spec_id=flow.spec_id, chain=chain),
                    )
                )
            continue

        if not incoming:
            continue

        if flow.dst_kind == "return":
            for label in incoming:
                spliced = (*label.provenance.chain, call_step, *flow.fragment)
                out.add(with_replaced_chain(label, spliced))
        elif flow.dst_kind == "sink" and flow.spec_id is not None:
            for label in incoming:
                if label.spec_id != flow.spec_id:
                    continue
                _emit_interproc_sink(flow, label.provenance.chain, call, ctx)
    return frozenset(out)


def _summary_inputs(
    flow: SummaryFlow,
    arg_labels: list[frozenset[TaintLabel]],
    receiver_labels: frozenset[TaintLabel],
) -> frozenset[TaintLabel]:
    """The caller-side labels feeding a summary flow's source endpoint."""
    if flow.src_kind == "param" and flow.src_index is not None:
        if 0 <= flow.src_index < len(arg_labels):
            return arg_labels[flow.src_index]
        return frozenset()
    if flow.src_kind == "self":
        return receiver_labels
    return frozenset()


def _emit_interproc_sink(
    flow: SummaryFlow,
    caller_chain: tuple[WitnessStep, ...],
    call: IRCall,
    ctx: PropagationContext,
) -> None:
    """Record an interprocedural sink finding with a spliced witness."""
    if flow.spec_id is None or flow.sink_location is None:
        return
    spec = _spec_by_id(ctx.specs, flow.spec_id)
    if spec is None:
        return
    call_step = make_step(WitnessRole.PROPAGATOR, call.location, f"call {call.callee_path}")
    witness = (*caller_chain, call_step, *flow.fragment)
    ctx.findings.append(InterprocSink(spec=spec, sink_location=flow.sink_location, witness=witness))


def _spec_by_id(specs: Sequence[DetectorSpec], spec_id: str) -> DetectorSpec | None:
    for spec in specs:
        if spec.id == spec_id:
            return spec
    return None


def _merge(labels: frozenset[TaintLabel] | set[TaintLabel]) -> frozenset[TaintLabel]:
    """Collapse to one best-provenance label per ``spec_id`` (delegates to env)."""
    from scanipy.engine.taint_state import _merge_labels

    return _merge_labels(frozenset(labels))
