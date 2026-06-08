<!-- SPDX-License-Identifier: Apache-2.0 -->
# IR reference — the shared intermediate representation

> The contract between the **Python frontend** (`scanipy.frontends.python_frontend`)
> and the engine. The frontend *produces* the IR; the matcher
> (`scanipy.engine.matcher`) and the taint engine (`scanipy.engine.taint`)
> *consume* it. The canonical dataclass definitions live in
> [`src/scanipy/ir.py`](../src/scanipy/ir.py); this document is the prose
> contract and the honest scope statement (principle **P7**).

The IR is a small tree of **frozen dataclasses** built from the standard-library
`ast`. It normalizes the constructs taint analysis cares about while keeping
enough source fidelity — a `scanipy.models.Location` on every node — that the
engine can build a witness without ever re-walking `ast`.

## Invariants

| | Invariant | Why |
|---|---|---|
| **Detector-agnostic (P4)** | `ir.py` knows nothing about taint, sources, sinks, sanitizers, or CWEs. | The engine owns all detection logic. |
| **No `ast` leak** | `ir.py` imports only `scanipy.models`. `ast` lives only in `python_frontend.py` and `resolver.py`. | The engine never imports `ast`. |
| **Deterministic (P3)** | Every collection is a source-ordered tuple. No `dict`/`set` iteration order leaks into the IR. | Byte-identical output across runs. |
| **Frozen / hashable** | Every node is an immutable frozen dataclass; two parses of the same file compare and hash equal. | Cheap caching + a determinism check. |

## Node inventory

### Module & scopes

* **`IRModule`** — `path`, `imports` (module-level `ImportTable`),
  `module_scope` (the synthetic `<module>` scope), and `functions` — *every*
  scope, including `module_scope` at index 0, in source order. `parent_index`
  and `scope_index` references index into `functions`.
* **`IRFunction`** — one scope: the module body, a `def`/`async def`, a `lambda`,
  or a comprehension/generator. A `class` body is **not** its own scope: its
  statements are inlined into the enclosing scope's CFG (so class-level
  sources/sinks are seen), while each method is its own `IRFunction`. Carries
  `name`, dotted `qualname`, `params`,
  the CFG (`body_blocks` + `entry_block_index`), `parent_index` (closure link;
  `None` only for `<module>`), `is_lambda`, `is_async`, `location`, and
  `local_imports` (this scope's import table chained ahead of its parents').
* **`IRParam`** — a formal parameter: `name`, positional `index`, `kind`
  (`"posonly"` | `"arg"` | `"vararg"` | `"kwonly"` | `"kwarg"`), `location`,
  `has_default`. Independent of the (deferred) DSL `parameter` source kind.
* **`IRBlock`** — a basic block: `index`, a `statements` tuple, and `successors`
  (block indices). See [CFG](#control-flow-graph).

### Statements (`Stmt`)

`IRAssign` (covers `=`, `:=`, annotated-with-value, `for`/`with`/`except`
bindings; `is_aug=True` for `+=` and friends), `IRExprStmt`, `IRReturn`,
`IRDelete`, `IRImportStmt`.

### Expressions (`Expr`)

`IRName`, `IRAttribute`, `IRCall`, `IRKeyword`, `IRLiteral`, `IRBinOp`,
`IRBoolOp`, `IRIfExp`, `IRJoinedStr`, `IRFormattedValue`, `IRContainer`,
`IRComprehension`, `IRSubscript`, `IRStarred`, `IRLambda`, and `IRUnknown`.

### Targets (`Target`)

`IRNameTarget`, `IRAttrTarget`, `IRSubscriptTarget`, `IRStarTarget`,
`IRTupleTarget`.

### Open node set — `IRUnknown`

Any `ast` construct the frontend does not model (e.g. `await`, `yield`,
`match`-case patterns) lowers to `IRUnknown(raw_repr=<ast class name>)` instead
of crashing. The engine treats it as opaque (no taint structure).

## Calls

`IRCall` separates the data the engine and matcher need:

* **`callee_path`** — the import-resolved dotted path of the callee
  (`"os.system"`, `"subprocess.run"`, `"conn.cursor.execute"`), or `None` when
  the callee is not a name/attribute chain (e.g. `foo()()`). A `None` path is a
  no-match, never an error.
* **`receiver`** — the method receiver expression (`callee.value` when the callee
  is an attribute), else `None`.
* **`args`** — the ordered **written positional** arguments, receiver excluded
  and index-addressable (so a sink restriction `args: [0]` selects the first
  written argument). A `*args` splat appears as an `IRStarred` element.
* **`kwargs`** — the written keyword arguments in source order; `name=None`
  marks a `**kwargs` splat. Each value keeps its literal-ness: `shell=True` is
  `IRKeyword("shell", IRLiteral(value=True, is_constant=True))`, while
  `shell=flag` carries an `IRName` (so the engine can require a literal `True`).

## Control-flow graph

The **frontend owns the CFG**; the engine consumes it and does *not* rebuild
one. Each `IRFunction` holds `body_blocks`, numbered in creation order.

* Straight-line code is a single block.
* `if`/`for`/`while`/`with`/`try` split blocks and create **join blocks**
  (more than one predecessor). At a join the engine **unions** taint — a value
  sanitized on one branch but not another stays tainted (the load-bearing P5
  rule).
* Loops add a **back-edge** to their header; the engine iterates to a bounded
  fixpoint rather than unrolling.
* `return`/`raise`/`break`/`continue` end a block. `break` links to the loop's
  join; `continue` links back to the header.
* The `test` of an `if`/`while`, the `iter` of a `for`, and a `with` context
  expression are emitted as statements so calls inside them are visible.

## Locations

Every node carries `scanipy.models.Location(file, line, column, end_line,
end_column)` with **1-based line** and **0-based column**, mirroring `ast`. End
positions are populated when `ast` provides them (Python ≥ 3.10).

## Import / alias canonicalization

`resolver.build_import_table` records every binding import in source order —
**including imports nested inside control-flow blocks** (`if`/`for`/`while`/
`with`/`try`, their `orelse`/`finalbody`, and `except` handlers) — and
`resolver.canonical_dotted` rewrites a name/attribute chain's *root* through the
table. This is the load-bearing step that prevents silent false negatives: all
four import styles canonicalize to the **same** dotted path, whether the import
is at module top level or guarded by control flow (e.g. `if cond: import os as o`
then `o.system(x)` still resolves to `os.system`). Recursion stops at scope
boundaries (`def`/`async def`/`class`/`lambda`), which build their own chained
tables.

| Source | `callee_path` |
|---|---|
| `import os; os.system(x)` | `os.system` |
| `import os as o; o.system(x)` | `os.system` |
| `from os import system; system(x)` | `os.system` |
| `from os import system as s; s(x)` | `os.system` |
| `from subprocess import run; run(x)` | `subprocess.run` |
| `import os.path as p; p.join(x)` | `os.path.join` |

A name rooted in a **local variable** is *not* rewritten, so value-rooted method
chains are preserved: `conn.cursor.execute(sql)` yields
`callee_path == "conn.cursor.execute"`, which both `*.execute` and
`*.cursor.execute` patterns can match.

## The matcher seam (`ResolvedNode`)

The matcher (work package C) consumes a small **structural** view of an
`IRCall`/`IRAttribute` via its own `ResolvedNode` protocol. The IR deliberately
does **not** import the DSL or define that protocol (to stay detector-agnostic
and cycle-free), so conformance is **not** literal field-name structural typing —
the engine adapts the IR to `ResolvedNode` with this mapping:

| `ResolvedNode` field | Source in the IR |
|---|---|
| `kind` | the node's concrete type (`IRCall` → `call`, `IRAttribute` → `attribute`, an `IRImportStmt` entry → `import`, `IRParam` → `parameter`) |
| `dotted_name` | `IRCall.callee_path` / `IRAttribute.canonical` / the import canonical / the param name |
| `arg_count` | `len(IRCall.args)` |
| `keywords` | `{kw.name: kw for kw in IRCall.kwargs if kw.name is not None}` |
| `KeywordValue.is_literal` | `isinstance(kw.value, IRLiteral) and kw.value.is_constant` |
| `KeywordValue.literal_value` | `kw.value.value` |
| `location` | `node.location` |

For a method call on an opaque-but-known tail (e.g. `get_conn().execute(...)`),
the chain root is a call, so `callee_path` is `None` in v1; such sites do not
match dotted patterns. (Emitting a tail-only `*.execute` name is a possible
future refinement.)

## Error / skip contract

`PythonFrontend.parse(path)` returns `None` — **never raises** — on a
`SyntaxError`, `UnicodeDecodeError`, `OSError` (missing/unreadable file),
`ValueError` (e.g. source containing a null byte), or `RecursionError` (a
parseable-but-deeply-nested file that exceeds the interpreter's recursion limit
in either `ast.parse` or lowering). The scan driver skips the file and may log
`skipped <path>`; a single bad file never aborts a scan.

## Documented unsoundness & out of scope (P7)

The IR is **best-effort, not sound**. First, what *is* now handled (so this list
stays honest about its own scope):

* **Imports nested in control flow** (`if cond: import os as o`, an import inside
  a `try`/`with`/`for`/`while` body, `orelse`, `finalbody`, or `except` handler)
  **are** canonicalized — `build_import_table` recurses into those bodies, so a
  guarded import no longer produces a silent false negative.
* **Class-level sources/sinks are captured.** A class body is inlined into the
  enclosing scope's CFG (it is not its own taint scope), so `class C: y =
  f(input())` surfaces the call. Methods remain their own `IRFunction` (parented
  to the class's enclosing scope) and are lowered normally.

Honest remaining limitations:

* **Aliasing through mutation.** Taint is tracked per access path, not per heap
  object: `b = a; sink(b)` is caught, but mutating a shared object through one
  alias and reading via another is missed.
* **Dynamic subscripts.** Only constant indices (`a[0]`, `d['k']`) are tracked
  precisely (`is_const_index=True`); a dynamic index is conservative
  (`is_const_index=False`) and the engine keeps the whole container tainted.
* **Star / relative imports.** `from m import *` is recorded as an opaque marker
  and resolves no names; relative imports (`from . import x`) are recorded but
  not resolved to an absolute dotted path (no misleading canonical).
* **Class-body import aliasing.** Because a class body is inlined into the
  enclosing scope, an import *inside* a class body resolves through the
  *enclosing* table, not a per-class one: `class C: import os as o; x =
  o.system(...)` will not canonicalize `o` to `os` (an uncommon shape; building a
  per-class table is out of scope for v1). Module/function-level aliased imports
  are unaffected.
* **Implicit / control-dependence flows.** `if tainted: x = "a"` is *not* tracked
  — only explicit data flow is modeled. Tracking implicit flows explodes false
  positives.
* **Closures / free variables.** Nested scopes are linked by `parent_index`, but
  free-variable taint across the closure boundary is not propagated in v1.
* **`match` statements & some async constructs.** `match`-case patterns and
  unmodeled expressions (`await`, `yield`) lower to `IRUnknown`.
* **Deeply-nested files are skipped, not analyzed.** A parseable file nested
  deeper than the interpreter's recursion limit raises `RecursionError` in
  `ast.parse` or lowering; `parse()` catches it and returns `None` (the file is
  skipped rather than crashing the scan — see the error/skip contract above).

P5's one-sidedness covers **sanitizers** only (a missing sanitizer is noise, a
false positive — never a silently-suppressed real vulnerability); it is *not* a
claim of overall soundness.
