# SPDX-License-Identifier: Apache-2.0
"""The taint propagation engine: ``TaintEngine.analyze`` (``ENGINE_6`` / ``ENGINE_9``).

The engine consumes the normalized :class:`~scanipy.ir.IRModule` produced by the
Python frontend plus the active :class:`~scanipy.dsl.DetectorSpec` pack and returns
witness-backed :class:`~scanipy.models.Finding` objects (P2). It runs in two
deterministic phases per module (P3):

#. **Summaries** (:mod:`scanipy.engine.summaries`) — a TITO :class:`FunctionSummary`
   per in-file function, computed to a bounded fixpoint over the call graph so
   intra-file interprocedural flows reach their sinks.
#. **Intraprocedural dataflow** (this module) — a flow-sensitive forward worklist
   over each function's CFG. Sources seed labels, assignments kill-then-reassign,
   propagators move taint, sanitizers clean one-sided, and a tainted value
   reaching a (constrained) sink argument emits a finding.

The engine is class-agnostic (P4): it iterates ``self._specs`` and performs only
generic operations (match a :class:`~scanipy.dsl.Pattern`, move/kill/seed labels,
splice witnesses). No CWE, library, or detector name appears in engine code — all
detection knowledge lives in the YAML specs. Analysis is local and in-process
(P1): no network, no file writes.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence

from scanipy.dsl import DetectorSpec, Pattern
from scanipy.engine.matcher import match
from scanipy.engine.propagation import (
    InterprocSink,
    PropagationContext,
    access_path_of,
    expr_taint,
)
from scanipy.engine.taint_state import (
    AccessPath,
    TaintEnv,
    TaintLabel,
    empty_env,
)
from scanipy.engine.witness import (
    build_witness,
    finding_fingerprint,
    make_step,
)
from scanipy.ir import (
    Expr,
    IRAssign,
    IRAttribute,
    IRBinOp,
    IRBoolOp,
    IRCall,
    IRComprehension,
    IRContainer,
    IRExprStmt,
    IRFormattedValue,
    IRFunction,
    IRIfExp,
    IRJoinedStr,
    IRModule,
    IRReturn,
    IRStarred,
    IRSubscript,
    Stmt,
    Target,
)
from scanipy.models import Finding, Location, WitnessRole, WitnessStep

# Per-block re-visit multiplier: a monotone lattice guarantees a fixpoint; this is
# a safety net so a malformed CFG can never loop forever.
FIXPOINT_CAP = 8


class TaintEngine:
    """Runs taint analysis for a set of detector specs."""

    def __init__(self, specs: Sequence[DetectorSpec]) -> None:
        self._specs: tuple[DetectorSpec, ...] = tuple(specs)

    @property
    def specs(self) -> tuple[DetectorSpec, ...]:
        return self._specs

    def analyze(self, module: object) -> list[Finding]:
        """Analyze one parsed module and return its sorted, deduped findings.

        Raises :class:`TypeError` if ``module`` is not an :class:`~scanipy.ir.IRModule`.
        """
        if not isinstance(module, IRModule):
            raise TypeError(
                f"TaintEngine.analyze expects a scanipy.ir.IRModule, got {type(module).__name__!r}"
            )

        # Deterministic spec order everywhere (P3).
        specs = tuple(sorted(self._specs, key=lambda s: s.id))

        # Phase 1: function summaries (imported lazily to avoid an import cycle).
        from scanipy.engine.summaries import build_callee_resolver, compute_summaries

        summaries = compute_summaries(module, specs)
        resolver = build_callee_resolver(module)

        # Phase 2: intraprocedural dataflow over every function (incl. <module>).
        raw: list[Finding] = []
        for fn in sorted(module.functions, key=lambda f: f.qualname):
            ctx = PropagationContext(specs=specs, summaries=summaries, callee_resolver=resolver)
            raw.extend(analyze_function(fn, ctx))

        return _finalize(raw)


# ---------------------------------------------------------------------------
# Intraprocedural dataflow
# ---------------------------------------------------------------------------


def analyze_function(fn: IRFunction, ctx: PropagationContext) -> list[Finding]:
    """Run the forward flow-sensitive taint pass over one function's CFG."""
    result = _run_dataflow(fn, ctx, entry_env=empty_env())
    findings: list[Finding] = []
    # Collect interprocedural sink hits only from the converged-env emission pass,
    # so a non-converged intermediate state never leaks a spurious witness.
    ctx.findings.clear()
    for block in fn.body_blocks:
        env = result.in_env.get(block.index, empty_env())
        for stmt in block.statements:
            env = _transfer(stmt, env, ctx, findings)
    for hit in ctx.findings:
        findings.append(_finding_from_interproc(hit))
    return findings


class _DataflowResult:
    """Per-block in-envs at the fixpoint (used to re-run transfers for emission)."""

    def __init__(self, in_env: dict[int, TaintEnv]) -> None:
        self.in_env = in_env


def _run_dataflow(fn: IRFunction, ctx: PropagationContext, entry_env: TaintEnv) -> _DataflowResult:
    """Compute the fixpoint in-env for every block (join = union, P5)."""
    blocks = {b.index: b for b in fn.body_blocks}
    preds: dict[int, list[int]] = {idx: [] for idx in blocks}
    for block in fn.body_blocks:
        for succ in block.successors:
            if succ in preds:
                preds[succ].append(block.index)

    in_env: dict[int, TaintEnv] = {idx: empty_env() for idx in blocks}
    out_env: dict[int, TaintEnv] = {idx: empty_env() for idx in blocks}
    in_env[fn.entry_block_index] = entry_env

    # Monotone lattice + finite height ⇒ a fixpoint; the cap is a safety net.
    cap = FIXPOINT_CAP * (len(blocks) + 1) ** 2 + len(blocks)
    worklist = sorted(blocks)
    iterations = 0
    while worklist and iterations < cap:
        iterations += 1
        idx = worklist.pop(0)
        block = blocks[idx]
        joined = entry_env if idx == fn.entry_block_index else empty_env()
        for pred in preds[idx]:
            joined = joined.join(out_env[pred])
        in_env[idx] = joined
        # Transfer over the block (no emission here — emission re-runs later).
        env = joined
        for stmt in block.statements:
            env = _transfer(stmt, env, ctx, findings=None)
        if env != out_env[idx]:
            out_env[idx] = env
            for succ in block.successors:
                if succ in blocks and succ not in worklist:
                    worklist.append(succ)
        worklist.sort()
    return _DataflowResult(in_env=in_env)


# ---------------------------------------------------------------------------
# Statement transfer
# ---------------------------------------------------------------------------


def _transfer(
    stmt: Stmt,
    env: TaintEnv,
    ctx: PropagationContext,
    findings: list[Finding] | None,
) -> TaintEnv:
    """Apply one statement to the env; emit sink findings when ``findings`` given.

    During the emission pass (``findings`` is not ``None``) every top-level call
    expression is evaluated via :func:`expr_taint`; that drives in-file summary
    application, whose side effect records interprocedural sink hits into
    ``ctx.findings`` (collected by :func:`analyze_function`).
    """
    if findings is not None:
        _detect_sinks(stmt, env, ctx, findings)
        if isinstance(stmt, IRExprStmt):
            expr_taint(stmt.value, env, ctx)
        elif isinstance(stmt, IRReturn) and stmt.value is not None:
            expr_taint(stmt.value, env, ctx)

    if isinstance(stmt, IRAssign):
        return _transfer_assign(stmt, env, ctx)
    # IRDelete / IRImportStmt bind no values the engine tracks.
    return env


def _transfer_assign(stmt: IRAssign, env: TaintEnv, ctx: PropagationContext) -> TaintEnv:
    """Update the env for an assignment (kill-then-seed, with unpack + augment)."""
    rhs = expr_taint(stmt.value, env, ctx)
    new_env = env
    for target in stmt.targets:
        new_env = _assign_target(target, rhs, new_env, stmt.is_aug)
    return new_env


def _assign_target(
    target: Target, labels: frozenset[TaintLabel], env: TaintEnv, is_aug: bool
) -> TaintEnv:
    """Bind ``labels`` to one (possibly nested) target (conservative unpack union)."""
    from scanipy.ir import IRStarTarget, IRTupleTarget

    if isinstance(target, IRTupleTarget):
        # Conservative: each unpacked element receives the whole RHS taint union.
        new_env = env
        for element in target.elements:
            new_env = _assign_target(element, labels, new_env, is_aug)
        return new_env
    if isinstance(target, IRStarTarget):
        return _assign_target(target.target, labels, env, is_aug)

    ap = _target_access_path(target)
    if ap is None:
        return env
    if is_aug:
        return env.assign(ap, env.get(ap) | labels)
    return env.assign(ap, labels)


def _target_access_path(target: Target) -> AccessPath | None:
    """Reduce an assignment target to a bounded :class:`AccessPath`, or ``None``."""
    from scanipy.engine.taint_state import AccessStep
    from scanipy.ir import IRAttrTarget, IRNameTarget, IRSubscriptTarget

    if isinstance(target, IRNameTarget):
        return AccessPath(base=target.name)
    if isinstance(target, IRAttrTarget):
        base = access_path_of(target.value)
        if base is None:
            return None
        return base.extend(AccessStep(kind="attr", value=target.attr))
    if isinstance(target, IRSubscriptTarget):
        base = access_path_of(target.value)
        if base is None:
            return None
        if target.is_const_index:
            return base.extend(AccessStep(kind="index", value=repr(target.const_index)))
        return base  # dynamic index taints the whole container
    return None


# ---------------------------------------------------------------------------
# Sink detection
# ---------------------------------------------------------------------------


def _detect_sinks(
    stmt: Stmt, env: TaintEnv, ctx: PropagationContext, findings: list[Finding]
) -> None:
    """Emit a finding for every tainted, constrained sink call in ``stmt``."""
    for call in _iter_calls_in_stmt(stmt):
        for spec in ctx.specs:
            for pattern in spec.sinks:
                _check_sink(spec, pattern, call, env, ctx, findings)


def _check_sink(
    spec: DetectorSpec,
    pattern: Pattern,
    call: IRCall,
    env: TaintEnv,
    ctx: PropagationContext,
    findings: list[Finding],
) -> None:
    """If ``call`` matches a sink pattern and a checked arg is tainted, emit."""
    result = match(pattern, call)
    if result is None:
        return
    for index in result.arg_indices:
        if index >= len(call.args):
            continue
        arg = call.args[index]
        labels = expr_taint(arg, env, ctx)
        for label in labels:
            if label.spec_id != spec.id:
                continue
            sink_step = make_step(WitnessRole.SINK, call.location, f"sink {result.dotted_name}")
            witness = build_witness(label.provenance.chain, sink_step)
            findings.append(_make_finding(spec, call.location, witness))


def _make_finding(spec: DetectorSpec, sink: Location, witness: tuple[WitnessStep, ...]) -> Finding:
    """Build a :class:`~scanipy.models.Finding` from a matched spec + witness."""
    return Finding(
        detector_id=spec.id,
        cwe=spec.cwe,
        severity=spec.severity,
        message=spec.message,
        location=sink,
        witness=witness,
        fingerprint=None,
    )


def _finding_from_interproc(hit: InterprocSink) -> Finding:
    """Build a finding from an interprocedural sink hit (spliced witness)."""
    return _make_finding(hit.spec, hit.sink_location, hit.witness)


# ---------------------------------------------------------------------------
# Call iteration
# ---------------------------------------------------------------------------


def _iter_calls_in_stmt(stmt: Stmt) -> Iterator[IRCall]:
    """Yield every :class:`~scanipy.ir.IRCall` syntactically inside ``stmt``."""
    if isinstance(stmt, IRAssign):
        yield from _iter_calls_in_expr(stmt.value)
    elif isinstance(stmt, IRExprStmt):
        yield from _iter_calls_in_expr(stmt.value)
    elif isinstance(stmt, IRReturn) and stmt.value is not None:
        yield from _iter_calls_in_expr(stmt.value)


def _iter_calls_in_expr(expr: Expr) -> Iterator[IRCall]:
    """Yield every nested :class:`~scanipy.ir.IRCall` within an expression."""
    if isinstance(expr, IRCall):
        yield expr
        if expr.receiver is not None:
            yield from _iter_calls_in_expr(expr.receiver)
        for arg in expr.args:
            yield from _iter_calls_in_expr(arg)
        for kw in expr.kwargs:
            yield from _iter_calls_in_expr(kw.value)
        return
    if isinstance(expr, IRAttribute):
        yield from _iter_calls_in_expr(expr.value)
    elif isinstance(expr, IRSubscript):
        yield from _iter_calls_in_expr(expr.value)
        yield from _iter_calls_in_expr(expr.index)
    elif isinstance(expr, IRBinOp):
        yield from _iter_calls_in_expr(expr.left)
        yield from _iter_calls_in_expr(expr.right)
    elif isinstance(expr, IRBoolOp):
        for value in expr.values:
            yield from _iter_calls_in_expr(value)
    elif isinstance(expr, IRIfExp):
        yield from _iter_calls_in_expr(expr.test)
        yield from _iter_calls_in_expr(expr.body)
        yield from _iter_calls_in_expr(expr.orelse)
    elif isinstance(expr, IRJoinedStr):
        for value in expr.values:
            yield from _iter_calls_in_expr(value)
    elif isinstance(expr, IRFormattedValue):
        yield from _iter_calls_in_expr(expr.value)
    elif isinstance(expr, IRContainer):
        for element in expr.elements:
            yield from _iter_calls_in_expr(element)
        for key in expr.keys:
            if key is not None:
                yield from _iter_calls_in_expr(key)
    elif isinstance(expr, IRComprehension):
        yield from _iter_calls_in_expr(expr.element)
        if expr.value is not None:
            yield from _iter_calls_in_expr(expr.value)
        for iterable in expr.iterables:
            yield from _iter_calls_in_expr(iterable)
    elif isinstance(expr, IRStarred):
        yield from _iter_calls_in_expr(expr.value)


# ---------------------------------------------------------------------------
# Finalization: dedup, fingerprint, sort
# ---------------------------------------------------------------------------


def _finalize(raw: list[Finding]) -> list[Finding]:
    """Dedup, assign fingerprints, and totally order the finding list (P3)."""
    best: dict[tuple[str, str, str], Finding] = {}
    for finding in raw:
        key = _dedup_key(finding)
        existing = best.get(key)
        if existing is None or _witness_better(finding.witness, existing.witness):
            best[key] = finding

    fingerprinted = [_with_fingerprint(f) for f in best.values()]
    fingerprinted.sort(key=_sort_key)
    return fingerprinted


def _dedup_key(finding: Finding) -> tuple[str, str, str]:
    """Dedup key: ``(detector_id, sink location, source-start location)``.

    Witnesses are source-first (P2): ``witness[0]`` is always the true SOURCE
    step, so its location is the real source-start used to dedup findings that
    share a detector and sink but originate at the same source.
    """
    sink = _loc_str(finding.location)
    source = finding.witness[0].location if finding.witness else finding.location
    return (finding.detector_id, sink, _loc_str(source))


def _witness_better(a: tuple[WitnessStep, ...], b: tuple[WitnessStep, ...]) -> bool:
    """True if witness ``a`` is canonically preferred (shorter, then smaller)."""
    from scanipy.engine.witness import better_chain

    return better_chain(b, a) is a and a != b


def _with_fingerprint(finding: Finding) -> Finding:
    """Return a copy of ``finding`` with its stable fingerprint filled in."""
    from dataclasses import replace

    fp = finding_fingerprint(finding.detector_id, finding.cwe, finding.location, finding.witness)
    return replace(finding, fingerprint=fp)


def _sort_key(finding: Finding) -> tuple[str, int, int, int, int, str, str]:
    """Total order: location, then detector id, then fingerprint tie-break (P3)."""
    loc = finding.location
    return (
        loc.file,
        loc.line,
        loc.column,
        loc.end_line if loc.end_line is not None else -1,
        loc.end_column if loc.end_column is not None else -1,
        finding.detector_id,
        finding.fingerprint or "",
    )


def _loc_str(loc: Location) -> str:
    end_line = loc.end_line if loc.end_line is not None else -1
    end_col = loc.end_column if loc.end_column is not None else -1
    return f"{loc.file}:{loc.line}:{loc.column}:{end_line}:{end_col}"
