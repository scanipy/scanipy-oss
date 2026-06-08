# SPDX-License-Identifier: Apache-2.0
"""The Python frontend: stdlib ``ast`` -> normalized :class:`~scanipy.ir.IRModule`.

:meth:`PythonFrontend.parse` reads one ``.py`` file, parses it with the standard
library :mod:`ast`, and lowers it to the shared, detector-agnostic IR (a per-scope
CFG of frozen dataclass nodes). It returns ``None`` — never raises — when the file
cannot be read or parsed (syntax error, decode error, OS error), so a single bad
file never aborts a scan.

``ast`` is used only here and in :mod:`scanipy.frontends.resolver`; the IR, the
matcher, and the engine never import ``ast``. This layer holds zero taint /
detector / CWE knowledge (P4).
"""

from __future__ import annotations

import ast
import tokenize
from pathlib import Path

from scanipy.frontends.base import Frontend
from scanipy.frontends.resolver import build_import_table, canonical_dotted
from scanipy.ir import (
    Expr,
    ImportTable,
    IRAssign,
    IRAttribute,
    IRAttrTarget,
    IRBinOp,
    IRBlock,
    IRBoolOp,
    IRCall,
    IRComprehension,
    IRContainer,
    IRDelete,
    IRExprStmt,
    IRFormattedValue,
    IRFunction,
    IRIfExp,
    IRImportStmt,
    IRJoinedStr,
    IRKeyword,
    IRLambda,
    IRLiteral,
    IRModule,
    IRName,
    IRNameTarget,
    IRParam,
    IRReturn,
    IRStarred,
    IRStarTarget,
    IRSubscript,
    IRSubscriptTarget,
    IRTupleTarget,
    IRUnknown,
    Stmt,
    Target,
)
from scanipy.models import Location

# Operator symbol tables (kept tiny + explicit for determinism).
_BINOP_SYMBOLS: dict[type[ast.operator], str] = {
    ast.Add: "+",
    ast.Sub: "-",
    ast.Mult: "*",
    ast.Div: "/",
    ast.FloorDiv: "//",
    ast.Mod: "%",
    ast.Pow: "**",
    ast.LShift: "<<",
    ast.RShift: ">>",
    ast.BitOr: "|",
    ast.BitAnd: "&",
    ast.BitXor: "^",
    ast.MatMult: "@",
}
_BOOLOP_SYMBOLS: dict[type[ast.boolop], str] = {ast.And: "and", ast.Or: "or"}

# ast statement nodes that begin/contain control flow (handled by the CFG builder).
_CONTROL_FLOW = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.With,
    ast.AsyncWith,
    ast.Try,
)


class PythonFrontend(Frontend):
    """Parses Python source via the standard-library AST into the shared IR."""

    language = "python"

    def parse(self, path: Path) -> IRModule | None:
        """Parse ``path`` into an :class:`IRModule`, or ``None`` on any failure.

        Reading uses :func:`tokenize.open` (PEP-263 encoding detection). Syntax,
        decoding, value, and OS errors are swallowed and reported as ``None`` so
        the scan driver can skip the file without crashing.
        """
        try:
            with tokenize.open(path) as handle:
                source = handle.read()
        except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
            return None
        try:
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, ValueError):
            # ValueError covers source containing null bytes.
            return None
        return _Lowerer(str(path)).lower_module(tree)


# ---------------------------------------------------------------------------
# Lowering
# ---------------------------------------------------------------------------

# ast nodes that introduce a new scope (own IRFunction).
_ScopeNode = (
    ast.FunctionDef
    | ast.AsyncFunctionDef
    | ast.Lambda
    | ast.ListComp
    | ast.SetComp
    | ast.DictComp
    | ast.GeneratorExp
)


class _Lowerer:
    """Lowers one ``ast.Module`` to an :class:`IRModule`.

    Two passes guarantee deterministic, source-ordered scope indices that can be
    referenced before a scope's own body is lowered (lambdas/comprehensions embed
    their ``scope_index``):

    1. :meth:`_collect_scopes` pre-orders every scope-creating node and assigns it
       a stable index (module scope is index 0).
    2. :meth:`_lower_scope` lowers each scope's body, resolving references through
       the scope's chained import table.
    """

    def __init__(self, file: str) -> None:
        self._file = file
        # ast scope node -> assigned IRFunction index (module is keyed by id 0).
        self._scope_index: dict[int, int] = {}
        # Ordered scope ast nodes (None placeholder at 0 for the module scope).
        self._scopes: list[ast.AST | None] = []
        # index -> parent index (module's parent is None).
        self._parents: list[int | None] = []
        # index -> chained ImportTable for that scope.
        self._tables: list[ImportTable] = []

    # -- locations ---------------------------------------------------------

    def _loc(self, node: ast.AST) -> Location:
        return Location(
            file=self._file,
            line=getattr(node, "lineno", 1),
            column=getattr(node, "col_offset", 0),
            end_line=getattr(node, "end_lineno", None),
            end_column=getattr(node, "end_col_offset", None),
        )

    # -- pass 1: scope discovery ------------------------------------------

    def lower_module(self, tree: ast.Module) -> IRModule:
        """Lower a parsed module into an :class:`IRModule`."""
        module_imports = build_import_table(tree.body, file=self._file)
        # Index 0 is the synthetic module scope.
        self._scopes.append(None)
        self._parents.append(None)
        self._tables.append(module_imports)
        self._scope_index[0] = 0  # sentinel; module uses parent key 0
        # Discover nested scopes in source pre-order (children of the module).
        self._collect_scopes(tree, parent=0, parent_table=module_imports)
        functions = self._lower_all_scopes(tree)
        module_scope = functions[0]
        return IRModule(
            path=self._file,
            imports=module_imports,
            module_scope=module_scope,
            functions=tuple(functions),
        )

    def _collect_scopes(self, node: ast.AST, *, parent: int, parent_table: ImportTable) -> None:
        """Pre-order walk assigning a stable index to each scope-creating node."""
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _ScopeNode):
                index = len(self._scopes)
                self._scope_index[id(child)] = index
                self._scopes.append(child)
                self._parents.append(parent)
                table = self._build_scope_table(child, parent_table)
                self._tables.append(table)
                self._collect_scopes(child, parent=index, parent_table=table)
            else:
                self._collect_scopes(child, parent=parent, parent_table=parent_table)

    def _build_scope_table(self, node: ast.AST, parent_table: ImportTable) -> ImportTable:
        """Chain a scope's local imports in front of its parent's table."""
        body = getattr(node, "body", None)
        local: ImportTable = ImportTable()
        if isinstance(body, list):
            local = build_import_table(
                [s for s in body if isinstance(s, ast.stmt)], file=self._file
            )
        # Local entries first (they shadow), then the parent's, for resolution order.
        return ImportTable(entries=parent_table.entries + local.entries)

    # -- pass 2: scope lowering -------------------------------------------

    def _lower_all_scopes(self, tree: ast.Module) -> list[IRFunction]:
        functions: list[IRFunction] = []
        for index, node in enumerate(self._scopes):
            if index == 0:
                functions.append(self._lower_module_scope(tree))
            else:
                assert node is not None  # noqa: S101 - structural invariant
                functions.append(self._lower_scope(node, index))
        return functions

    def _lower_module_scope(self, tree: ast.Module) -> IRFunction:
        table = self._tables[0]
        blocks = _CFGBuilder(self, table).build(tree.body)
        return IRFunction(
            name="<module>",
            qualname="<module>",
            params=(),
            body_blocks=blocks,
            entry_block_index=0,
            parent_index=None,
            is_lambda=False,
            is_async=False,
            location=Location(file=self._file, line=1, column=0),
            local_imports=table,
        )

    def _lower_scope(self, node: ast.AST, index: int) -> IRFunction:
        table = self._tables[index]
        parent = self._parents[index]
        qualname = self._qualname(index)
        if isinstance(node, ast.Lambda):
            return self._lower_lambda(node, index, parent, qualname, table)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return self._lower_comprehension_scope(node, index, parent, qualname, table)
        assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))  # noqa: S101
        return self._lower_function(node, index, parent, qualname, table)

    def _qualname(self, index: int) -> str:
        parts: list[str] = []
        cur: int | None = index
        while cur is not None and cur != 0:
            node = self._scopes[cur]
            parts.append(self._scope_name(node))
            cur = self._parents[cur]
        parts.reverse()
        return ".".join(parts) if parts else "<module>"

    @staticmethod
    def _scope_name(node: ast.AST | None) -> str:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
        if isinstance(node, ast.Lambda):
            return "<lambda>"
        if isinstance(node, ast.ListComp):
            return "<listcomp>"
        if isinstance(node, ast.SetComp):
            return "<setcomp>"
        if isinstance(node, ast.DictComp):
            return "<dictcomp>"
        if isinstance(node, ast.GeneratorExp):
            return "<genexpr>"
        return "<scope>"

    def _lower_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        index: int,
        parent: int | None,
        qualname: str,
        table: ImportTable,
    ) -> IRFunction:
        params = self._lower_params(node.args, table)
        blocks = _CFGBuilder(self, table).build(node.body)
        return IRFunction(
            name=node.name,
            qualname=qualname,
            params=params,
            body_blocks=blocks,
            entry_block_index=0,
            parent_index=parent,
            is_lambda=False,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            location=self._loc(node),
            local_imports=table,
        )

    def _lower_lambda(
        self,
        node: ast.Lambda,
        index: int,
        parent: int | None,
        qualname: str,
        table: ImportTable,
    ) -> IRFunction:
        params = self._lower_params(node.args, table)
        body_expr = self.lower_expr(node.body, table)
        ret = IRReturn(value=body_expr, location=self._loc(node.body))
        block = IRBlock(index=0, statements=(ret,), successors=())
        return IRFunction(
            name="<lambda>",
            qualname=qualname,
            params=params,
            body_blocks=(block,),
            entry_block_index=0,
            parent_index=parent,
            is_lambda=True,
            is_async=False,
            location=self._loc(node),
            local_imports=table,
        )

    def _lower_comprehension_scope(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
        index: int,
        parent: int | None,
        qualname: str,
        table: ImportTable,
    ) -> IRFunction:
        # The comprehension body binds its targets and evaluates element/iters as
        # statements so the engine sees the data flow inside the nested scope.
        statements: list[Stmt] = []
        for gen in node.generators:
            iter_expr = self.lower_expr(gen.iter, table)
            tgt = self.lower_target(gen.target)
            statements.append(
                IRAssign(
                    targets=(tgt,),
                    value=iter_expr,
                    is_aug=False,
                    location=self._loc(gen.target),
                )
            )
            for cond in gen.ifs:
                statements.append(
                    IRExprStmt(value=self.lower_expr(cond, table), location=self._loc(cond))
                )
        if isinstance(node, ast.DictComp):
            statements.append(
                IRExprStmt(value=self.lower_expr(node.key, table), location=self._loc(node.key))
            )
            statements.append(
                IRExprStmt(value=self.lower_expr(node.value, table), location=self._loc(node.value))
            )
        else:
            statements.append(
                IRExprStmt(value=self.lower_expr(node.elt, table), location=self._loc(node.elt))
            )
        block = IRBlock(index=0, statements=tuple(statements), successors=())
        return IRFunction(
            name=self._scope_name(node),
            qualname=qualname,
            params=(),
            body_blocks=(block,),
            entry_block_index=0,
            parent_index=parent,
            is_lambda=False,
            is_async=False,
            location=self._loc(node),
            local_imports=table,
        )

    def _lower_params(self, args: ast.arguments, table: ImportTable) -> tuple[IRParam, ...]:
        out: list[IRParam] = []
        idx = 0
        posonly = args.posonlyargs
        normal = args.args
        n_pos_defaults = len(args.defaults)
        n_pos_total = len(posonly) + len(normal)
        for offset, arg in enumerate(posonly):
            has_default = (n_pos_total - offset) <= n_pos_defaults
            out.append(self._param(arg, idx, "posonly", has_default))
            idx += 1
        for offset, arg in enumerate(normal):
            pos = len(posonly) + offset
            has_default = (n_pos_total - pos) <= n_pos_defaults
            out.append(self._param(arg, idx, "arg", has_default))
            idx += 1
        if args.vararg is not None:
            out.append(self._param(args.vararg, idx, "vararg", False))
            idx += 1
        for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
            out.append(self._param(arg, idx, "kwonly", default is not None))
            idx += 1
        if args.kwarg is not None:
            out.append(self._param(args.kwarg, idx, "kwarg", False))
            idx += 1
        return tuple(out)

    def _param(self, arg: ast.arg, index: int, kind: str, has_default: bool) -> IRParam:
        return IRParam(
            name=arg.arg,
            index=index,
            kind=kind,
            location=self._loc(arg),
            has_default=has_default,
        )

    def scope_index_of(self, node: ast.AST) -> int | None:
        """Return the IRFunction index assigned to a scope-creating ast node."""
        return self._scope_index.get(id(node))

    # -- expression lowering ----------------------------------------------

    def lower_expr(self, node: ast.expr, table: ImportTable) -> Expr:
        """Lower one ``ast.expr`` to an IR :data:`~scanipy.ir.Expr`."""
        loc = self._loc(node)
        if isinstance(node, ast.Name):
            return IRName(name=node.id, canonical=canonical_dotted(node, table), location=loc)
        if isinstance(node, ast.Attribute):
            return IRAttribute(
                value=self.lower_expr(node.value, table),
                attr=node.attr,
                canonical=canonical_dotted(node, table),
                location=loc,
            )
        if isinstance(node, ast.Call):
            return self._lower_call(node, table)
        if isinstance(node, ast.Constant):
            return IRLiteral(value=node.value, is_constant=True, location=loc)
        if isinstance(node, ast.BinOp):
            return IRBinOp(
                op=_BINOP_SYMBOLS.get(type(node.op), "?"),
                left=self.lower_expr(node.left, table),
                right=self.lower_expr(node.right, table),
                location=loc,
            )
        if isinstance(node, ast.BoolOp):
            return IRBoolOp(
                op=_BOOLOP_SYMBOLS.get(type(node.op), "?"),
                values=tuple(self.lower_expr(v, table) for v in node.values),
                location=loc,
            )
        if isinstance(node, ast.IfExp):
            return IRIfExp(
                test=self.lower_expr(node.test, table),
                body=self.lower_expr(node.body, table),
                orelse=self.lower_expr(node.orelse, table),
                location=loc,
            )
        if isinstance(node, ast.JoinedStr):
            return IRJoinedStr(
                values=tuple(self.lower_expr(v, table) for v in node.values), location=loc
            )
        if isinstance(node, ast.FormattedValue):
            return IRFormattedValue(value=self.lower_expr(node.value, table), location=loc)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._lower_sequence(node, table)
        if isinstance(node, ast.Dict):
            return self._lower_dict(node, table)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self._lower_comprehension_expr(node, table)
        if isinstance(node, ast.Subscript):
            return self._lower_subscript(node, table)
        if isinstance(node, ast.Starred):
            return IRStarred(value=self.lower_expr(node.value, table), location=loc)
        if isinstance(node, ast.Lambda):
            return IRLambda(scope_index=self.scope_index_of(node), location=loc)
        if isinstance(node, ast.NamedExpr):
            # Walrus as an expression: surface the assigned value (the binding is
            # also lowered as a statement by the CFG builder).
            return self.lower_expr(node.value, table)
        return IRUnknown(raw_repr=type(node).__name__, location=loc)

    def _lower_call(self, node: ast.Call, table: ImportTable) -> IRCall:
        callee = self.lower_expr(node.func, table)
        receiver: Expr | None = None
        if isinstance(node.func, ast.Attribute):
            receiver = self.lower_expr(node.func.value, table)
        args = tuple(self.lower_expr(a, table) for a in node.args)
        kwargs = tuple(
            IRKeyword(
                name=kw.arg,
                value=self.lower_expr(kw.value, table),
                location=self._loc(kw.value),
            )
            for kw in node.keywords
        )
        return IRCall(
            callee=callee,
            callee_path=canonical_dotted(node.func, table),
            receiver=receiver,
            args=args,
            kwargs=kwargs,
            location=self._loc(node),
        )

    def _lower_sequence(
        self, node: ast.List | ast.Tuple | ast.Set, table: ImportTable
    ) -> IRContainer:
        kind = {ast.List: "list", ast.Tuple: "tuple", ast.Set: "set"}[type(node)]
        return IRContainer(
            kind=kind,
            elements=tuple(self.lower_expr(e, table) for e in node.elts),
            keys=(),
            location=self._loc(node),
        )

    def _lower_dict(self, node: ast.Dict, table: ImportTable) -> IRContainer:
        elements = tuple(self.lower_expr(v, table) for v in node.values)
        keys = tuple(self.lower_expr(k, table) if k is not None else None for k in node.keys)
        return IRContainer(kind="dict", elements=elements, keys=keys, location=self._loc(node))

    def _lower_comprehension_expr(
        self,
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
        table: ImportTable,
    ) -> IRComprehension:
        kind = {
            ast.ListComp: "list",
            ast.SetComp: "set",
            ast.GeneratorExp: "generator",
            ast.DictComp: "dict",
        }[type(node)]
        iterables = tuple(self.lower_expr(gen.iter, table) for gen in node.generators)
        if isinstance(node, ast.DictComp):
            element = self.lower_expr(node.key, table)
            value: Expr | None = self.lower_expr(node.value, table)
        else:
            element = self.lower_expr(node.elt, table)
            value = None
        return IRComprehension(
            kind=kind,
            element=element,
            value=value,
            iterables=iterables,
            scope_index=self.scope_index_of(node),
            location=self._loc(node),
        )

    def _lower_subscript(self, node: ast.Subscript, table: ImportTable) -> IRSubscript:
        is_const, const_index = _const_subscript(node.slice)
        return IRSubscript(
            value=self.lower_expr(node.value, table),
            index=self.lower_expr(node.slice, table),
            is_const_index=is_const,
            const_index=const_index,
            location=self._loc(node),
        )

    # -- target lowering ---------------------------------------------------

    def lower_target(self, node: ast.expr) -> Target:
        """Lower an assignment target to an IR :data:`~scanipy.ir.Target`."""
        loc = self._loc(node)
        if isinstance(node, ast.Name):
            return IRNameTarget(name=node.id, location=loc)
        if isinstance(node, ast.Attribute):
            return IRAttrTarget(
                value=self.lower_expr(node.value, self._tables[0]),
                attr=node.attr,
                location=loc,
            )
        if isinstance(node, ast.Subscript):
            is_const, const_index = _const_subscript(node.slice)
            return IRSubscriptTarget(
                value=self.lower_expr(node.value, self._tables[0]),
                index=self.lower_expr(node.slice, self._tables[0]),
                is_const_index=is_const,
                const_index=const_index,
                location=loc,
            )
        if isinstance(node, ast.Starred):
            return IRStarTarget(target=self.lower_target(node.value), location=loc)
        if isinstance(node, (ast.Tuple, ast.List)):
            return IRTupleTarget(
                elements=tuple(self.lower_target(e) for e in node.elts), location=loc
            )
        # Unknown target shape: model as a synthetic name so binding is visible.
        return IRNameTarget(name=f"<{type(node).__name__}>", location=loc)


class _CFGBuilder:
    """Builds a per-scope basic-block CFG from a list of ``ast`` statements.

    Straight-line code accumulates into one block; ``if``/``for``/``while``/
    ``with``/``try`` split blocks and create join blocks (the engine unions taint
    at joins). Loops add a back-edge to their header (no unrolling; the engine
    iterates to a bounded fixpoint). ``return``/``break``/``continue`` terminate a
    block. Blocks are numbered in creation order (determinism).
    """

    def __init__(self, lowerer: _Lowerer, table: ImportTable) -> None:
        self._low = lowerer
        self._table = table
        self._blocks: list[list[Stmt]] = []
        self._succ: list[list[int]] = []
        # Targets for break/continue within the innermost loop.
        self._loop_stack: list[tuple[int, list[int]]] = []  # (header, break_targets)

    def build(self, body: list[ast.stmt]) -> tuple[IRBlock, ...]:
        entry = self._new_block()
        exits = self._emit_seq(body, [entry])
        # Ensure a terminal block exists; remaining exits simply have no successor.
        del exits
        return tuple(
            IRBlock(index=i, statements=tuple(stmts), successors=tuple(self._succ[i]))
            for i, stmts in enumerate(self._blocks)
        )

    def _new_block(self) -> int:
        self._blocks.append([])
        self._succ.append([])
        return len(self._blocks) - 1

    def _link(self, src: int, dst: int) -> None:
        if dst not in self._succ[src]:
            self._succ[src].append(dst)

    def _emit_seq(self, body: list[ast.stmt], heads: list[int]) -> list[int]:
        """Emit a statement sequence; return the set of exit block indices."""
        current = heads
        for stmt in body:
            current = self._emit_stmt(stmt, current)
            if not current:
                break  # unreachable tail after a terminator
        return current

    def _emit_stmt(self, stmt: ast.stmt, heads: list[int]) -> list[int]:
        if isinstance(stmt, _CONTROL_FLOW):
            return self._emit_control(stmt, heads)
        if isinstance(stmt, (ast.Return, ast.Break, ast.Continue, ast.Raise)):
            return self._emit_terminator(stmt, heads)
        # Straight-line statement: append to every incoming block.
        ir_stmts = self._lower_stmt(stmt)
        for h in heads:
            self._blocks[h].extend(ir_stmts)
        return heads

    def _emit_terminator(self, stmt: ast.stmt, heads: list[int]) -> list[int]:
        if isinstance(stmt, ast.Return):
            ir = IRReturn(
                value=self._low.lower_expr(stmt.value, self._table) if stmt.value else None,
                location=self._low._loc(stmt),
            )
            for h in heads:
                self._blocks[h].append(ir)
            return []
        if isinstance(stmt, ast.Raise):
            # Model raise as ending the block (no normal successor).
            return []
        if isinstance(stmt, ast.Break) and self._loop_stack:
            for h in heads:
                self._loop_stack[-1][1].append(h)
            return []
        if isinstance(stmt, ast.Continue) and self._loop_stack:
            header = self._loop_stack[-1][0]
            for h in heads:
                self._link(h, header)
            return []
        return []

    def _emit_control(self, stmt: ast.stmt, heads: list[int]) -> list[int]:
        if isinstance(stmt, ast.If):
            return self._emit_if(stmt, heads)
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            return self._emit_for(stmt, heads)
        if isinstance(stmt, ast.While):
            return self._emit_while(stmt, heads)
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            return self._emit_with(stmt, heads)
        if isinstance(stmt, ast.Try):
            return self._emit_try(stmt, heads)
        return heads

    def _emit_if(self, stmt: ast.If, heads: list[int]) -> list[int]:
        # Evaluate the test in the incoming blocks.
        test_stmt = IRExprStmt(
            value=self._low.lower_expr(stmt.test, self._table),
            location=self._low._loc(stmt.test),
        )
        for h in heads:
            self._blocks[h].append(test_stmt)
        then_entry = self._new_block()
        for h in heads:
            self._link(h, then_entry)
        then_exits = self._emit_seq(stmt.body, [then_entry])
        if stmt.orelse:
            else_entry = self._new_block()
            for h in heads:
                self._link(h, else_entry)
            else_exits = self._emit_seq(stmt.orelse, [else_entry])
        else:
            # No else: control may fall straight to the join.
            else_exits = list(heads)
        join = self._new_block()
        for e in then_exits + else_exits:
            self._link(e, join)
        return [join]

    def _emit_for(self, stmt: ast.For | ast.AsyncFor, heads: list[int]) -> list[int]:
        iter_stmt = IRExprStmt(
            value=self._low.lower_expr(stmt.iter, self._table),
            location=self._low._loc(stmt.iter),
        )
        for h in heads:
            self._blocks[h].append(iter_stmt)
        header = self._new_block()
        for h in heads:
            self._link(h, header)
        # Bind the loop target at the header.
        target = self._low.lower_target(stmt.target)
        self._blocks[header].append(
            IRAssign(
                targets=(target,),
                value=self._low.lower_expr(stmt.iter, self._table),
                is_aug=False,
                location=self._low._loc(stmt.target),
            )
        )
        body_entry = self._new_block()
        self._link(header, body_entry)
        break_targets: list[int] = []
        self._loop_stack.append((header, break_targets))
        body_exits = self._emit_seq(stmt.body, [body_entry])
        self._loop_stack.pop()
        for e in body_exits:
            self._link(e, header)  # back-edge
        join = self._new_block()
        self._link(header, join)  # loop may not execute / completes
        for b in break_targets:
            self._link(b, join)
        if stmt.orelse:
            else_exits = self._emit_seq(stmt.orelse, [join])
            final = self._new_block()
            for e in else_exits:
                self._link(e, final)
            return [final]
        return [join]

    def _emit_while(self, stmt: ast.While, heads: list[int]) -> list[int]:
        header = self._new_block()
        for h in heads:
            self._link(h, header)
        self._blocks[header].append(
            IRExprStmt(
                value=self._low.lower_expr(stmt.test, self._table),
                location=self._low._loc(stmt.test),
            )
        )
        body_entry = self._new_block()
        self._link(header, body_entry)
        break_targets: list[int] = []
        self._loop_stack.append((header, break_targets))
        body_exits = self._emit_seq(stmt.body, [body_entry])
        self._loop_stack.pop()
        for e in body_exits:
            self._link(e, header)  # back-edge
        join = self._new_block()
        self._link(header, join)
        for b in break_targets:
            self._link(b, join)
        if stmt.orelse:
            else_exits = self._emit_seq(stmt.orelse, [join])
            final = self._new_block()
            for e in else_exits:
                self._link(e, final)
            return [final]
        return [join]

    def _emit_with(self, stmt: ast.With | ast.AsyncWith, heads: list[int]) -> list[int]:
        for item in stmt.items:
            ctx = self._low.lower_expr(item.context_expr, self._table)
            if item.optional_vars is not None:
                target = self._low.lower_target(item.optional_vars)
                bind = IRAssign(
                    targets=(target,),
                    value=ctx,
                    is_aug=False,
                    location=self._low._loc(item.optional_vars),
                )
                for h in heads:
                    self._blocks[h].append(bind)
            else:
                stmt_ir = IRExprStmt(value=ctx, location=self._low._loc(item.context_expr))
                for h in heads:
                    self._blocks[h].append(stmt_ir)
        return self._emit_seq(stmt.body, heads)

    def _emit_try(self, stmt: ast.Try, heads: list[int]) -> list[int]:
        body_exits = self._emit_seq(stmt.body, heads)
        # Each handler is reachable from the try body's entry blocks (conservative).
        handler_exits: list[int] = []
        for handler in stmt.handlers:
            h_entry = self._new_block()
            for h in heads:
                self._link(h, h_entry)
            if handler.name is not None:
                hloc = self._low._loc(handler)
                self._blocks[h_entry].append(
                    IRAssign(
                        targets=(IRNameTarget(name=handler.name, location=hloc),),
                        value=IRUnknown(raw_repr="ExceptHandler", location=hloc),
                        is_aug=False,
                        location=hloc,
                    )
                )
            handler_exits.extend(self._emit_seq(handler.body, [h_entry]))
        exits = body_exits + handler_exits
        if stmt.orelse:
            exits = self._emit_seq(stmt.orelse, exits)
        if stmt.finalbody:
            exits = self._emit_seq(stmt.finalbody, exits)
        return exits

    # -- straight-line statement lowering ---------------------------------

    def _lower_stmt(self, stmt: ast.stmt) -> list[Stmt]:
        loc = self._low._loc(stmt)
        if isinstance(stmt, ast.Assign):
            return [
                IRAssign(
                    targets=tuple(self._low.lower_target(t) for t in stmt.targets),
                    value=self._low.lower_expr(stmt.value, self._table),
                    is_aug=False,
                    location=loc,
                )
            ]
        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is None:
                return []  # bare annotation binds nothing
            return [
                IRAssign(
                    targets=(self._low.lower_target(stmt.target),),
                    value=self._low.lower_expr(stmt.value, self._table),
                    is_aug=False,
                    location=loc,
                )
            ]
        if isinstance(stmt, ast.AugAssign):
            return [
                IRAssign(
                    targets=(self._low.lower_target(stmt.target),),
                    value=self._low.lower_expr(stmt.value, self._table),
                    is_aug=True,
                    location=loc,
                )
            ]
        if isinstance(stmt, ast.Expr):
            return self._lower_expr_stmt(stmt)
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            entries = build_import_table([stmt], file=self._low._file).entries
            return [IRImportStmt(entries=entries, location=loc)]
        if isinstance(stmt, ast.Delete):
            return [
                IRDelete(
                    targets=tuple(self._low.lower_target(t) for t in stmt.targets), location=loc
                )
            ]
        if isinstance(stmt, (ast.Global, ast.Nonlocal, ast.Pass)):
            return []
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Definitions create scopes (already collected) or classes; nothing to
            # add to the enclosing block's data flow here.
            return []
        # Unknown statement: surface as an opaque expression statement.
        unknown = IRUnknown(raw_repr=type(stmt).__name__, location=loc)
        return [IRExprStmt(value=unknown, location=loc)]

    def _lower_expr_stmt(self, stmt: ast.Expr) -> list[Stmt]:
        out: list[Stmt] = []
        # Surface any walrus binding inside the expression as an assignment too.
        for named in _walrus_targets(stmt.value):
            assert isinstance(named.target, ast.Name)  # noqa: S101 - guarded by collector
            out.append(
                IRAssign(
                    targets=(IRNameTarget(name=named.target.id, location=self._low._loc(named)),),
                    value=self._low.lower_expr(named.value, self._table),
                    is_aug=False,
                    location=self._low._loc(named),
                )
            )
        out.append(
            IRExprStmt(
                value=self._low.lower_expr(stmt.value, self._table),
                location=self._low._loc(stmt),
            )
        )
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _const_subscript(slice_node: ast.expr) -> tuple[bool, object]:
    """Return ``(is_const, value)`` for a subscript index (``a[0]`` / ``d['k']``)."""
    if isinstance(slice_node, ast.Constant):
        return True, slice_node.value
    return False, None


def _walrus_targets(node: ast.expr) -> list[ast.NamedExpr]:
    """Collect walrus bindings in an expression (shallow, non-nested-scope)."""
    found: list[ast.NamedExpr] = []
    for child in ast.walk(node):
        if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
            found.append(child)
    return found
