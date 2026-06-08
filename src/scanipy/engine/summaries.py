# SPDX-License-Identifier: Apache-2.0
"""TITO function summaries for intra-file interprocedural taint (``ENGINE_7/8``).

The engine reaches taint across in-file function boundaries without inlining, via
*transfer-input/transfer-output* (TITO) summaries. For each function it records a
sorted set of :class:`~scanipy.engine.propagation.SummaryFlow` facts answering:

* which formal **param** (or ``self``, or an in-body **source**) taints the
  **return** value, and
* which param / self / source reaches which **sink** inside the function,

each carrying a witness *fragment* that is spliced into the caller at the call
site (so no callee re-analysis is needed — principle P2, P3 determinism).

Summaries are computed in reverse-topological order of the within-file call graph;
cyclic SCCs (recursion / mutual recursion) are solved by a **bounded monotone
worklist fixpoint** (:data:`SUMMARY_FIXPOINT_CAP`), so analysis always terminates.
The call graph is derived here from ``IRCall.callee_path`` matched against
in-file :class:`~scanipy.ir.IRFunction` qualnames (bare names resolve to
top-level functions; deeper method/nested resolution is approximate — P7).
"""

from __future__ import annotations

from collections.abc import Sequence

from scanipy.dsl import DetectorSpec
from scanipy.engine.matcher import match
from scanipy.engine.propagation import (
    FunctionSummary,
    PropagationContext,
    SummaryFlow,
    expr_taint,
)
from scanipy.engine.taint_state import (
    AccessPath,
    TaintEnv,
    TaintLabel,
    TaintProvenance,
    empty_env,
)
from scanipy.engine.witness import make_step
from scanipy.ir import (
    IRAssign,
    IRCall,
    IRFunction,
    IRModule,
    IRParam,
    IRReturn,
    Stmt,
)
from scanipy.models import WitnessRole, WitnessStep

# Max SCC re-analysis rounds: monotone (flows only added) + capped ⇒ termination.
SUMMARY_FIXPOINT_CAP = 8

# A reserved spec-id namespace for engine-internal symbolic param markers. It can
# never collide with a real detector id (which is dotted, e.g. python.injection.x).
_PARAM_MARKER_PREFIX = "\x00param\x00"


def _param_marker_id(index: int) -> str:
    """Spec-id of the symbolic taint marker for positional parameter ``index``."""
    return f"{_PARAM_MARKER_PREFIX}{index}"


def _self_marker_id() -> str:
    """Spec-id of the symbolic taint marker for the receiver (``self``)."""
    return f"{_PARAM_MARKER_PREFIX}self"


def _is_param_marker(spec_id: str) -> bool:
    return spec_id.startswith(_PARAM_MARKER_PREFIX)


def _marker_param_index(spec_id: str) -> int | None:
    rest = spec_id[len(_PARAM_MARKER_PREFIX) :]
    if rest == "self":
        return None
    return int(rest)


def compute_summaries(
    module: IRModule, specs: Sequence[DetectorSpec]
) -> dict[str, FunctionSummary]:
    """Compute a :class:`FunctionSummary` per in-file function (deterministic)."""
    functions = {fn.qualname: fn for fn in module.functions}
    call_graph = _build_call_graph(module, functions)
    order = _reverse_topo_sccs(functions, call_graph)
    resolver = build_callee_resolver(module)

    summaries: dict[str, FunctionSummary] = {}
    for scc in order:
        if len(scc) == 1 and scc[0] not in call_graph.get(scc[0], ()):  # singleton, non-self-rec
            qn = scc[0]
            summaries[qn] = _summarize_function(functions[qn], specs, summaries, resolver)
        else:
            _summarize_scc(scc, functions, specs, summaries, resolver)
    return summaries


def build_callee_resolver(module: IRModule) -> dict[str, str]:
    """Map every call's ``callee_path`` to the in-file qualname it resolves to.

    Mirrors the call-graph resolution so summary *application* (at call sites) and
    summary *computation* (the call graph) agree on which in-file function a
    method/aliased call targets (e.g. ``obj.run`` -> ``"run"``).
    """
    functions = {fn.qualname: fn for fn in module.functions}
    name_index = _function_name_index(functions)
    resolver: dict[str, str] = {}
    for fn in module.functions:
        for call in _iter_calls(fn):
            if call.callee_path is None:
                continue
            target = _resolve_callee(call.callee_path, name_index)
            if target is not None:
                resolver[call.callee_path] = target
    return resolver


# ---------------------------------------------------------------------------
# Call graph + SCC ordering
# ---------------------------------------------------------------------------


def _build_call_graph(
    module: IRModule, functions: dict[str, IRFunction]
) -> dict[str, tuple[str, ...]]:
    """Map each in-file qualname to its sorted in-file callee qualnames."""
    name_index = _function_name_index(functions)
    graph: dict[str, tuple[str, ...]] = {}
    for fn in module.functions:
        callees: set[str] = set()
        for call in _iter_calls(fn):
            target = _resolve_callee(call.callee_path, name_index)
            if target is not None and target != fn.qualname:
                callees.add(target)
            elif target == fn.qualname:
                callees.add(target)  # self-recursion edge
        graph[fn.qualname] = tuple(sorted(callees))
    return graph


def _function_name_index(functions: dict[str, IRFunction]) -> dict[str, str]:
    """Index resolvable call names (bare ``name`` -> qualname) for the call graph."""
    index: dict[str, str] = {}
    for qualname, fn in functions.items():
        index.setdefault(fn.name, qualname)
        index.setdefault(qualname, qualname)
    return index


def _resolve_callee(callee_path: str | None, name_index: dict[str, str]) -> str | None:
    """Resolve a call's dotted path to an in-file function qualname, if any."""
    if callee_path is None:
        return None
    if callee_path in name_index:
        return name_index[callee_path]
    # A method-style ``recv.helper`` resolves to a same-name top-level helper (P7).
    last = callee_path.rsplit(".", 1)[-1]
    return name_index.get(last)


def _reverse_topo_sccs(
    functions: dict[str, IRFunction], call_graph: dict[str, tuple[str, ...]]
) -> list[list[str]]:
    """Tarjan SCCs in reverse-topological order (callees before callers, P3)."""
    index_counter = [0]
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    result: list[list[str]] = []

    def strongconnect(node: str) -> None:
        indices[node] = index_counter[0]
        lowlink[node] = index_counter[0]
        index_counter[0] += 1
        stack.append(node)
        on_stack.add(node)
        for succ in call_graph.get(node, ()):
            if succ not in functions:
                continue
            if succ not in indices:
                strongconnect(succ)
                lowlink[node] = min(lowlink[node], lowlink[succ])
            elif succ in on_stack:
                lowlink[node] = min(lowlink[node], indices[succ])
        if lowlink[node] == indices[node]:
            component: list[str] = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.append(member)
                if member == node:
                    break
            result.append(sorted(component))

    for node in sorted(functions):
        if node not in indices:
            strongconnect(node)
    # Tarjan yields SCCs in reverse-topological order already (callees first).
    return result


# ---------------------------------------------------------------------------
# Summary computation
# ---------------------------------------------------------------------------


def _summarize_function(
    fn: IRFunction,
    specs: Sequence[DetectorSpec],
    summaries: dict[str, FunctionSummary],
    resolver: dict[str, str],
) -> FunctionSummary:
    """Analyze one function with symbolic param markers; harvest TITO flows."""
    ctx = PropagationContext(specs=specs, summaries=summaries, callee_resolver=resolver)
    entry_env = _seed_param_markers(fn)
    out_env = _function_fixpoint(fn, ctx, entry_env)

    flows: set[SummaryFlow] = set()

    # PARAM/SELF/SOURCE -> RETURN: inspect every return statement's value taint.
    for block in fn.body_blocks:
        env = out_env.get(block.index, empty_env())
        for stmt in block.statements:
            if isinstance(stmt, IRReturn) and stmt.value is not None:
                labels = expr_taint(stmt.value, env, ctx)
                for label in labels:
                    flow = _return_flow(label)
                    if flow is not None:
                        flows.add(flow)
            env = _summary_transfer(stmt, env, ctx)

    # PARAM/SELF/SOURCE -> SINK: re-run sink detection capturing marker provenance.
    flows |= _harvest_sink_flows(fn, ctx, entry_env)

    return FunctionSummary(qualname=fn.qualname, flows=tuple(sorted(flows, key=_flow_key)))


def _summarize_scc(
    scc: list[str],
    functions: dict[str, IRFunction],
    specs: Sequence[DetectorSpec],
    summaries: dict[str, FunctionSummary],
    resolver: dict[str, str],
) -> None:
    """Bounded monotone worklist fixpoint for a cyclic SCC (recursion-safe)."""
    for qn in scc:
        summaries[qn] = FunctionSummary(qualname=qn, flows=())
    for _ in range(SUMMARY_FIXPOINT_CAP):
        changed = False
        for qn in scc:
            new_summary = _summarize_function(functions[qn], specs, summaries, resolver)
            if new_summary.flows != summaries[qn].flows:
                summaries[qn] = new_summary
                changed = True
        if not changed:
            break


def _seed_param_markers(fn: IRFunction) -> TaintEnv:
    """Seed each positional / receiver parameter with a symbolic marker label."""
    env = empty_env()
    for param in fn.params:
        marker_id = _marker_for_param(param)
        if marker_id is None:
            continue
        step = make_step(WitnessRole.PROPAGATOR, param.location, f"parameter {param.name}")
        label = TaintLabel(
            spec_id=marker_id,
            provenance=TaintProvenance(spec_id=marker_id, chain=(step,)),
        )
        env = env.seed(AccessPath(base=param.name), frozenset({label}))
    return env


def _marker_for_param(param: IRParam) -> str | None:
    """Symbolic marker id for a parameter (positional index, or ``self``)."""
    if param.kind in ("posonly", "arg"):
        if param.index == 0 and param.name in ("self", "cls"):
            return _self_marker_id()
        return _param_marker_id(param.index)
    return None


def _function_fixpoint(
    fn: IRFunction, ctx: PropagationContext, entry_env: TaintEnv
) -> dict[int, TaintEnv]:
    """Forward fixpoint returning each block's converged in-env (union joins)."""
    blocks = {b.index: b for b in fn.body_blocks}
    preds: dict[int, list[int]] = {idx: [] for idx in blocks}
    for block in fn.body_blocks:
        for succ in block.successors:
            if succ in preds:
                preds[succ].append(block.index)

    in_env: dict[int, TaintEnv] = {idx: empty_env() for idx in blocks}
    out_env: dict[int, TaintEnv] = {idx: empty_env() for idx in blocks}

    cap = (len(blocks) + 1) * SUMMARY_FIXPOINT_CAP + len(blocks)
    worklist = sorted(blocks)
    iterations = 0
    while worklist and iterations < cap:
        iterations += 1
        idx = worklist.pop(0)
        joined = entry_env if idx == fn.entry_block_index else empty_env()
        for pred in preds[idx]:
            joined = joined.join(out_env[pred])
        in_env[idx] = joined
        env = joined
        for stmt in blocks[idx].statements:
            env = _summary_transfer(stmt, env, ctx)
        if env != out_env[idx]:
            out_env[idx] = env
            for succ in blocks[idx].successors:
                if succ in blocks and succ not in worklist:
                    worklist.append(succ)
        worklist.sort()
    return in_env


def _summary_transfer(stmt: Stmt, env: TaintEnv, ctx: PropagationContext) -> TaintEnv:
    """Assignment transfer used during summary computation (no sink emission)."""
    if isinstance(stmt, IRAssign):
        from scanipy.engine.taint import _assign_target

        rhs = expr_taint(stmt.value, env, ctx)
        new_env = env
        for target in stmt.targets:
            new_env = _assign_target(target, rhs, new_env, stmt.is_aug)
        return new_env
    return env


def _harvest_sink_flows(
    fn: IRFunction, ctx: PropagationContext, entry_env: TaintEnv
) -> set[SummaryFlow]:
    """Find param/self/source markers reaching sinks; build sink TITO flows."""
    out_env = _function_fixpoint(fn, ctx, entry_env)
    flows: set[SummaryFlow] = set()
    for block in fn.body_blocks:
        env = out_env.get(block.index, empty_env())
        for stmt in block.statements:
            for call in _iter_calls_in_stmt(stmt):
                flows |= _sink_flows_for_call(call, env, ctx)
            env = _summary_transfer(stmt, env, ctx)
    return flows


def _sink_flows_for_call(call: IRCall, env: TaintEnv, ctx: PropagationContext) -> set[SummaryFlow]:
    """Sink TITO flows: a marker/source reaching a sink arg inside the callee."""
    flows: set[SummaryFlow] = set()
    for spec in ctx.specs:
        for pattern in spec.sinks:
            result = match(pattern, call)
            if result is None:
                continue
            for index in result.arg_indices:
                if index >= len(call.args):
                    continue
                labels = expr_taint(call.args[index], env, ctx)
                sink_step = make_step(WitnessRole.SINK, call.location, f"sink {result.dotted_name}")
                for label in labels:
                    flow = _sink_flow(label, spec.id, sink_step, call)
                    if flow is not None:
                        flows.add(flow)
    return flows


def _return_flow(label: TaintLabel) -> SummaryFlow | None:
    """Build a ``*->return`` summary flow from a label reaching a return value."""
    if _is_param_marker(label.spec_id):
        index = _marker_param_index(label.spec_id)
        # Strip the synthetic param-entry step from the fragment for return flows.
        return SummaryFlow(
            src_kind="self" if index is None else "param",
            src_index=index,
            dst_kind="return",
            spec_id=None,
            fragment=label.provenance.chain[1:],
        )
    # A real in-body source reaching the return: callee introduces the taint.
    return SummaryFlow(
        src_kind="source",
        src_index=None,
        dst_kind="return",
        spec_id=label.spec_id,
        fragment=label.provenance.chain,
    )


def _sink_flow(
    label: TaintLabel, spec_id: str, sink_step: WitnessStep, call: IRCall
) -> SummaryFlow | None:
    """Build a ``*->sink`` summary flow from a label reaching a sink argument."""
    if _is_param_marker(label.spec_id):
        index = _marker_param_index(label.spec_id)
        fragment = (*label.provenance.chain[1:], sink_step)
        return SummaryFlow(
            src_kind="self" if index is None else "param",
            src_index=index,
            dst_kind="sink",
            spec_id=spec_id,
            fragment=fragment,
            sink_location=call.location,
        )
    # An in-body source reaching an in-body sink is a fully-internal flow: it is
    # already emitted when this function is analyzed intraprocedurally in phase 2,
    # so summarizing it would double-report it (with a malformed witness) at every
    # call site. Only marker (param/self) flows produce interprocedural findings.
    return None


def _flow_key(flow: SummaryFlow) -> tuple[str, int, str, str]:
    """A total ordering key for summary flows (determinism, P3)."""
    return (
        flow.src_kind,
        flow.src_index if flow.src_index is not None else -1,
        flow.dst_kind,
        flow.spec_id or "",
    )


# ---------------------------------------------------------------------------
# Call iteration helpers (shared shape with taint.py, kept local + minimal)
# ---------------------------------------------------------------------------


def _iter_calls(fn: IRFunction) -> list[IRCall]:
    """Every call site in a function (for call-graph construction)."""
    calls: list[IRCall] = []
    for block in fn.body_blocks:
        for stmt in block.statements:
            calls.extend(_iter_calls_in_stmt(stmt))
    return calls


def _iter_calls_in_stmt(stmt: Stmt) -> list[IRCall]:
    """Delegate to the engine's call walker to avoid duplicate traversal logic."""
    from scanipy.engine.taint import _iter_calls_in_stmt as walk

    return list(walk(stmt))
