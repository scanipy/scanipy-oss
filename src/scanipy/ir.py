# SPDX-License-Identifier: Apache-2.0
"""The shared, normalized intermediate representation (IR).

This is the single IR produced by the Python frontend
(:mod:`scanipy.frontends.python_frontend`) and consumed by the matcher
(:mod:`scanipy.engine.matcher`) and the taint engine
(:mod:`scanipy.engine.taint`). It is a small tree of *frozen* dataclasses that
normalizes the constructs taint analysis cares about (calls, attribute chains,
assignments with full binder coverage, control flow) while preserving enough
``ast`` fidelity — via :class:`scanipy.models.Location` on every node — to build
a witness without ever re-walking ``ast``.

Design invariants (see ``docs/ir-reference.md``):

* **Detector-agnostic (P4).** Nothing here knows about taint, sources, sinks,
  sanitizers, or CWEs. The engine owns all of that.
* **No ``ast`` dependency.** This module imports only the standard library and
  :class:`scanipy.models.Location`; the engine never needs to import ``ast``.
* **Deterministic (P3).** Every collection is an ordered tuple emitted in source
  order; no ``dict``/``set`` iteration order leaks into the IR.
* **Frozen.** Every node is an immutable, hashable frozen dataclass.

The matcher consumes a small structural view of these nodes (its ``ResolvedNode``
protocol). The mapping from these concrete fields to that protocol is documented
in ``docs/ir-reference.md``; this module intentionally does *not* depend on the
DSL or the matcher to keep the IR neutral and cycle-free.
"""

from __future__ import annotations

from dataclasses import dataclass

from scanipy.models import Location

# ---------------------------------------------------------------------------
# Import / alias resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ImportEntry:
    """One resolved name binding introduced by an ``import`` statement.

    ``local_name`` is the name as bound in the importing module (the alias when
    one is given, else the imported name). ``canonical`` is the dotted path the
    local name resolves to, used to canonicalize references for matching.
    ``kind`` is ``"module"`` for ``import X``/``import X.Y``/``import X as Y``,
    ``"name"`` for ``from M import N``/``from M import N as A``, and ``"star"`` for
    a ``from M import *`` marker (whose bound names are unknown).
    """

    local_name: str
    canonical: str
    kind: str  # "module" | "name" | "star"
    asname: str | None
    location: Location


@dataclass(frozen=True)
class ImportTable:
    """The per-scope table of local-name -> canonical-path bindings.

    Entries are stored in source order (determinism). Scopes chain to their
    parents: a function's local imports are resolved first, then the module's.
    """

    entries: tuple[ImportEntry, ...] = ()

    def resolve(self, local_name: str) -> ImportEntry | None:
        """Return the entry binding ``local_name``, or ``None`` if unbound.

        The *last* matching entry wins so a later import in the same scope
        shadows an earlier one, mirroring Python rebinding semantics.
        """
        found: ImportEntry | None = None
        for entry in self.entries:
            if entry.local_name == local_name:
                found = entry
        return found


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IRName:
    """A bare name reference (``x``).

    ``canonical`` is the import-resolved dotted path when ``name`` is an imported
    module/name (e.g. ``os`` -> ``"os"``), else ``None`` for ordinary locals.
    """

    name: str
    canonical: str | None
    location: Location


@dataclass(frozen=True)
class IRAttribute:
    """An attribute access (``value.attr``).

    ``canonical`` is the full import-resolved dotted path for the chain when it
    is rooted in a name/attribute chain (e.g. ``os.path`` -> ``"os.path"``), else
    ``None`` (e.g. the chain is rooted in a call).
    """

    value: Expr
    attr: str
    canonical: str | None
    location: Location


@dataclass(frozen=True)
class IRKeyword:
    """A keyword argument of a call.

    ``name`` is the keyword name, or ``None`` for a ``**kwargs`` splat.
    """

    name: str | None
    value: Expr
    location: Location


@dataclass(frozen=True)
class IRCall:
    """A call site (``callee(*args, **kwargs)``).

    ``callee_path`` is the import-resolved dotted path of the callee
    (e.g. ``"os.system"``, ``"subprocess.run"``, ``"conn.cursor.execute"``), or
    ``None`` when the callee is not a name/attribute chain (e.g. ``foo()()``).
    ``receiver`` is the attribute chain's base expression for a method call
    (``callee.value`` when the callee is an attribute), else ``None``.
    ``args`` are the ordered written positional arguments (receiver excluded);
    a ``*args`` splat appears as an :class:`IRStarred`. ``kwargs`` are the
    written keyword arguments in source order.
    """

    callee: Expr
    callee_path: str | None
    receiver: Expr | None
    args: tuple[Expr, ...]
    kwargs: tuple[IRKeyword, ...]
    location: Location


@dataclass(frozen=True)
class IRLiteral:
    """A constant literal (``"x"``, ``1``, ``True``, ``None``, ...).

    ``is_constant`` is ``True`` for genuine compile-time constants; it lets the
    engine/matcher distinguish ``shell=True`` (constant) from ``shell=flag``.
    """

    value: object
    is_constant: bool
    location: Location


@dataclass(frozen=True)
class IRBinOp:
    """A binary operation (``left <op> right``).

    ``op`` is the operator symbol (``"+"``, ``"%"``, ``"*"``, ...). The engine
    uses ``+`` and ``%`` on strings as default taint propagators.
    """

    op: str
    left: Expr
    right: Expr
    location: Location


@dataclass(frozen=True)
class IRBoolOp:
    """A boolean operation (``a and b``, ``a or b``)."""

    op: str  # "and" | "or"
    values: tuple[Expr, ...]
    location: Location


@dataclass(frozen=True)
class IRIfExp:
    """A conditional expression (``body if test else orelse``)."""

    test: Expr
    body: Expr
    orelse: Expr
    location: Location


@dataclass(frozen=True)
class IRFormattedValue:
    """One interpolated field of an f-string (``{value!conv:spec}``)."""

    value: Expr
    location: Location


@dataclass(frozen=True)
class IRJoinedStr:
    """An f-string (``f"...{x}..."``).

    ``values`` interleaves :class:`IRLiteral` text parts and
    :class:`IRFormattedValue` interpolations. The engine treats it as a default
    string propagator.
    """

    values: tuple[Expr, ...]
    location: Location


@dataclass(frozen=True)
class IRContainer:
    """A literal container build (``[..]``, ``(..)``, ``{..}``, ``{k: v}``).

    ``kind`` is ``"list"``, ``"tuple"``, ``"set"``, or ``"dict"``. For dicts,
    ``elements`` holds the values and ``keys`` holds the matching keys (a key may
    be ``None`` for ``**spread``); otherwise ``keys`` is empty.
    """

    kind: str
    elements: tuple[Expr, ...]
    keys: tuple[Expr | None, ...]
    location: Location


@dataclass(frozen=True)
class IRComprehension:
    """A comprehension or generator expression.

    ``element`` is the produced element (or key/value pair flattened into
    ``element``/``value`` for dict comprehensions). The comprehension introduces
    a nested scope; ``scope_index`` points at the corresponding
    :class:`IRFunction` in :attr:`IRModule.functions`.
    """

    kind: str  # "list" | "set" | "dict" | "generator"
    element: Expr
    value: Expr | None
    iterables: tuple[Expr, ...]
    scope_index: int | None
    location: Location


@dataclass(frozen=True)
class IRSubscript:
    """A subscript (``value[index]``).

    ``is_const_index`` is ``True`` when the index is a constant; ``const_index``
    then holds that constant value (e.g. ``0`` or ``"k"``). Dynamic indices are
    tracked conservatively by the engine (whole container).
    """

    value: Expr
    index: Expr
    is_const_index: bool
    const_index: object
    location: Location


@dataclass(frozen=True)
class IRStarred:
    """A starred expression in a call/assignment (``*x``)."""

    value: Expr
    location: Location


@dataclass(frozen=True)
class IRLambda:
    """A lambda expression.

    ``scope_index`` points at the :class:`IRFunction` holding the lambda body in
    :attr:`IRModule.functions`.
    """

    scope_index: int | None
    location: Location


@dataclass(frozen=True)
class IRUnknown:
    """An expression construct the frontend does not model.

    ``raw_repr`` is the ``ast`` node class name (e.g. ``"Await"``) for debugging.
    The engine treats it as opaque (no taint structure), never crashing on it.
    """

    raw_repr: str
    location: Location


# ---------------------------------------------------------------------------
# Assignment targets
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IRNameTarget:
    """A name being bound (``x = ...``)."""

    name: str
    location: Location


@dataclass(frozen=True)
class IRAttrTarget:
    """An attribute being bound (``x.a = ...``)."""

    value: Expr
    attr: str
    location: Location


@dataclass(frozen=True)
class IRSubscriptTarget:
    """A subscript being bound (``x[i] = ...``)."""

    value: Expr
    index: Expr
    is_const_index: bool
    const_index: object
    location: Location


@dataclass(frozen=True)
class IRStarTarget:
    """A starred target in unpacking (``*rest`` in ``a, *rest = it``)."""

    target: Target
    location: Location


@dataclass(frozen=True)
class IRTupleTarget:
    """A tuple/list unpacking target (``a, b = ...``)."""

    elements: tuple[Target, ...]
    location: Location


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IRAssign:
    """An assignment (``targets = value``).

    ``is_aug`` marks an augmented assignment (``x += value``): the LHS is both
    read and written, so the engine must not kill the prior taint of the target.
    Walrus ``(x := value)`` and ``for``/``with``/``except`` bindings are also
    lowered to :class:`IRAssign` with a single target.
    """

    targets: tuple[Target, ...]
    value: Expr
    is_aug: bool
    location: Location


@dataclass(frozen=True)
class IRExprStmt:
    """An expression evaluated for effect (a bare call, a loop ``iter``, ...)."""

    value: Expr
    location: Location


@dataclass(frozen=True)
class IRReturn:
    """A ``return`` statement (``value`` is ``None`` for a bare ``return``)."""

    value: Expr | None
    location: Location


@dataclass(frozen=True)
class IRDelete:
    """A ``del`` statement over one or more targets."""

    targets: tuple[Target, ...]
    location: Location


@dataclass(frozen=True)
class IRImportStmt:
    """An ``import``/``from ... import`` statement.

    ``entries`` are the bindings it introduces (also folded into the enclosing
    scope's :class:`ImportTable`); kept as a statement so the CFG/engine can see
    where an import textually occurs.
    """

    entries: tuple[ImportEntry, ...]
    location: Location


# ---------------------------------------------------------------------------
# Control-flow graph & scopes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IRBlock:
    """A basic block: a straight-line statement sequence + successor edges.

    ``index`` is the block's position in its function's ``body_blocks`` tuple.
    ``successors`` are the indices of blocks control may flow to; a join block
    has more than one predecessor and the engine *unions* taint there. Loop
    headers have back-edges (the engine iterates to a bounded fixpoint).
    """

    index: int
    statements: tuple[Stmt, ...]
    successors: tuple[int, ...]


@dataclass(frozen=True)
class IRParam:
    """A formal parameter.

    ``index`` is the positional index (counting posonly + normal positional
    params, in order); ``kind`` is one of ``"posonly"``, ``"arg"``, ``"vararg"``,
    ``"kwonly"``, or ``"kwarg"``.
    """

    name: str
    index: int
    kind: str
    location: Location
    has_default: bool = False


@dataclass(frozen=True)
class IRFunction:
    """A scope: the module body, a ``def``/``async def``, a lambda, or a comprehension.

    ``qualname`` is the dotted scope path (e.g. ``"outer.inner"``). ``body_blocks``
    is the scope's CFG (always non-empty; the entry is ``body_blocks[entry_block_index]``).
    ``parent_index`` links to the enclosing scope in :attr:`IRModule.functions`
    (``None`` only for the module scope). ``local_imports`` are imports bound
    inside this scope (chained to parents by the resolver during lowering).
    """

    name: str
    qualname: str
    params: tuple[IRParam, ...]
    body_blocks: tuple[IRBlock, ...]
    entry_block_index: int
    parent_index: int | None
    is_lambda: bool
    is_async: bool
    location: Location
    local_imports: ImportTable = ImportTable()


@dataclass(frozen=True)
class IRModule:
    """A parsed Python module.

    ``module_scope`` is the synthetic ``"<module>"`` scope holding top-level
    statements; ``functions`` holds every scope (including ``module_scope`` at a
    stable position) in deterministic source order so ``parent_index`` and
    ``scope_index`` references are resolvable.
    """

    path: str
    imports: ImportTable
    module_scope: IRFunction
    functions: tuple[IRFunction, ...]


# ---------------------------------------------------------------------------
# Union aliases (defined after all members exist for runtime ``X | Y``)
# ---------------------------------------------------------------------------

Expr = (
    IRName
    | IRAttribute
    | IRCall
    | IRLiteral
    | IRBinOp
    | IRBoolOp
    | IRIfExp
    | IRJoinedStr
    | IRFormattedValue
    | IRContainer
    | IRComprehension
    | IRSubscript
    | IRStarred
    | IRLambda
    | IRUnknown
)

Target = IRNameTarget | IRAttrTarget | IRSubscriptTarget | IRStarTarget | IRTupleTarget

Stmt = IRAssign | IRExprStmt | IRReturn | IRDelete | IRImportStmt

__all__ = [
    "Expr",
    "IRAssign",
    "IRAttrTarget",
    "IRAttribute",
    "IRBinOp",
    "IRBlock",
    "IRBoolOp",
    "IRCall",
    "IRComprehension",
    "IRContainer",
    "IRDelete",
    "IRExprStmt",
    "IRFormattedValue",
    "IRFunction",
    "IRIfExp",
    "IRImportStmt",
    "IRJoinedStr",
    "IRKeyword",
    "IRLambda",
    "IRLiteral",
    "IRModule",
    "IRName",
    "IRNameTarget",
    "IRParam",
    "IRReturn",
    "IRStarTarget",
    "IRStarred",
    "IRSubscript",
    "IRSubscriptTarget",
    "IRTupleTarget",
    "IRUnknown",
    "ImportEntry",
    "ImportTable",
    "Stmt",
    "Target",
]
