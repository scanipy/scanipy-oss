# scanipy taint engine reference

> **Status: v1 (0.2.0).** This documents the taint engine that consumes the
> [taint-DSL specs](dsl-reference.md) and the normalized
> [IR](ir-reference.md). It is the companion to the DSL reference: the DSL is
> *what* to detect; this is *how* the engine finds it. Detection knowledge lives
> entirely in the YAML specs — the engine is class-agnostic (principle **P4**).

The engine takes an `IRModule` (from `scanipy.frontends.PythonFrontend.parse`) and
the active `DetectorSpec` pack and returns a deterministic, witness-backed
`list[Finding]`:

```python
from scanipy.frontends.python_frontend import PythonFrontend
from scanipy.registry import load_builtin_detectors
from scanipy.engine import TaintEngine

module = PythonFrontend().parse(path)            # IRModule | None
findings = TaintEngine(load_builtin_detectors()).analyze(module)
```

`TaintEngine.analyze` raises `TypeError` on anything that is not an `IRModule`. It
performs **no network I/O and no file writes** (principle **P1**); each module is
analyzed in isolation with no cross-file or global mutable state.

---

## 1. Pipeline

Analysis runs in two deterministic phases per module (P3):

```
IRModule ──▶ Phase 1: function summaries (TITO)      summaries.py
         │     reverse-topo over the in-file call graph; bounded SCC fixpoint
         ▼
            Phase 2: intraprocedural dataflow          taint.py
              flow-sensitive forward worklist per CFG, union at joins
         ▼
            dedup ─▶ fingerprint ─▶ total-order sort ─▶ list[Finding]
```

Module layout:

| File | Responsibility |
|---|---|
| `engine/taint_state.py` | Access-path taint lattice (`AccessPath`, `TaintLabel`, `TaintEnv`). |
| `engine/witness.py` | Witness chain selection + `sha256` fingerprints. |
| `engine/propagation.py` | `expr_taint`: generic built-in + DSL propagation, calls, summaries. |
| `engine/summaries.py` | TITO `FunctionSummary` computation + call-graph SCC fixpoint. |
| `engine/taint.py` | `TaintEngine.analyze`, the CFG dataflow, sink emission, finalization. |
| `engine/matcher.py` | Pure `Pattern` ↔ IR matcher (shared with the frontend). |

---

## 2. Taint state: access paths

Taint is keyed by an **access path** — a base variable plus a bounded suffix of
`.attr` / constant-`[index]` steps (depth cap `STEPS_CAP = 2`):

- `x`, `x.a`, `x.a.b`, `d["k"]` are tracked precisely.
- At the cap a deeper path **collapses to its prefix** and over-approximates: a
  read of any sibling under the collapsed prefix sees the taint. This biases
  toward false positives, **never** false negatives (P5-safe), and deliberately
  diverges from tools that drop deep taint.
- A **dynamic** subscript `x[i]` (non-constant `i`) taints the whole container
  `x` (collapse to base) on write, and reads from a tainted container conservatively.

The environment (`TaintEnv`) is an immutable `AccessPath → frozenset[TaintLabel]`
map. Every operation returns a new env:

- **assign** — kill the target path (and its extensions), then bind the RHS labels
  (kill-then-reassign; reassigning `x` clears prior `x.a`).
- **augment** (`x += t`) — union the RHS taint with the target's existing taint.
- **sanitize** — remove one spec's labels at a path (and its extensions), **one
  sided** (only on the path where the sanitizer demonstrably runs).
- **join** — per-path **union** of label sets (see §4).

For bounded state and deterministic witnesses, the env keeps a **single best
provenance per `(access_path, spec_id)`** (shortest witness chain, then
lexicographically smallest). This also gives the lattice finite height, so the
forward dataflow always reaches a fixpoint.

---

## 3. Propagation (`expr_taint`)

`expr_taint(expr, env, ctx)` returns the labels flowing out of an expression. It
is detector-agnostic — every rule applies to every spec equally (P4):

- **Sources.** Any sub-expression matching a spec's `source` pattern introduces a
  fresh label for that spec. Because source detection is part of `expr_taint`, a
  source nested directly in a sink (`os.system(input())`) still seeds taint, and
  one site can seed several specs (`input()` feeds both os-command and sql).
- **Names / attributes / subscripts** — look up the access path in the env.
- **String-shaped operators** — `+`, `%`, `*` carry taint from either operand;
  f-strings, containers, comprehensions, and `and`/`or`/conditional value-unions
  carry the taint of their values. The *condition* of an `if`-expression is **not**
  propagated (implicit / control-dependence flow is out of scope — P7).
- **`str` methods** (`.strip()`, `.format()`, `.replace()`, …) — a built-in
  default carries receiver/argument taint to the return value.
- **Calls** — dispatched as follows:
  1. A **sanitizer** match cleans that spec's taint from the return value.
  2. Matching **DSL propagators** move taint per their `flow` (`from → to`).
  3. An **in-file summary** (§5) propagates param/self/source → return and emits
     interprocedural sink findings.
  4. An **unknown external callee** falls back to `any-arg → return`
     (conservative pass-through — FP-biased, P5-safe, documented P7).

---

## 4. Intraprocedural dataflow

For each function the engine runs a flow-sensitive forward worklist over the
frontend's per-function CFG (`IRBlock` + `successors`):

- a block's in-env is the **union** of its predecessors' out-envs;
- statements transfer the env (assign / augment / sanitize);
- **joins union, never intersect** — the load-bearing P5 rule. Code sanitized on
  only one branch of an `if` is **still flagged**, because the other branch falls
  through to the join carrying live taint.
- loops iterate to a **bounded fixpoint** (monotone lattice + a `FIXPOINT_CAP`
  safety net) so analysis always terminates.

**Sink emission.** For each sink `Pattern` that matches a call, the engine checks
the restricted positional argument indices (`Pattern.args`, receiver-excluded). If
a checked argument carries an unsanitized label for that spec and the `when`
constraints hold, it emits a `Finding` whose witness is the label's provenance
chain plus a final `SINK` step. Severity / CWE / message / id are **copied** from
the matched spec; the engine invents nothing.

---

## 5. Interprocedural summaries (TITO)

Intra-file interprocedural reach is achieved with **transfer-input/transfer-output
(TITO) function summaries**, not inlining. The engine:

1. builds the in-file call graph by matching `IRCall.callee_path` against in-file
   function qualnames (bare names resolve to top-level functions; method / nested
   resolution is approximate — P7);
2. condenses it into SCCs (deterministic Tarjan over sorted qualnames) and
   processes them in **reverse-topological** order (callees before callers);
3. summarizes each function by analyzing it once with each formal parameter seeded
   as a **symbolic marker** label, harvesting the flows that reach the return value
   or a sink:
   - `param_i → return`, `self → return`, in-body `source → return`,
   - `param_i → sink S`, `self → sink S`, in-body `source → sink S`,
   each carrying a witness **fragment** for splicing;
4. solves cyclic SCCs (recursion / mutual recursion) with a **bounded monotone
   worklist fixpoint** (`SUMMARY_FIXPOINT_CAP`) — flows only ever grow, so it
   terminates.

**Application + witness splicing.** At a call site, a caller-side label feeding a
`param_i → sink` flow emits a finding whose witness is:

```
[caller chain: source → … → arg]  +  [call-site PROPAGATOR: arg enters param]  +  [callee fragment ending in SINK]
```

A `param_i → return` flow continues the label (with the splice) into the caller's
value, so chained wrappers compose.

---

## 6. Determinism (P3)

Output is byte-identical across runs, machines, and spec-input order:

- specs are iterated in sorted `id` order; functions by qualname; blocks by index;
  summary flows by a total key. No `dict` / `set` iteration order leaks out.
- **Witness selection** keeps the canonical chain per `(spec, sink, source)`:
  shortest, then the lexicographically smallest tuple of
  `(role, file, line, column, end_line, end_column)`.
- **Dedup** key: `(detector_id, sink location, source-start location)`. This also
  collapses a sink matched by two overlapping patterns (e.g. `*.cursor.execute`
  and `*.execute`) into one finding.
- **Fingerprint** (`Finding.fingerprint`): a `sha256` hex digest over
  `detector_id`, `cwe`, the sink location, and the ordered witness step tuples —
  derived **only** from field values (no `id()` / `hash()` / `PYTHONHASHSEED`).
- **Final sort** key ends in the fingerprint, making the order **total** even when
  two findings share a location and detector id.

---

## 7. Honest scope (P7)

The OSS engine is single-language (Python) and intra-file. Known limitations,
documented rather than hidden:

- **No cross-file / whole-program analysis.** Summaries are intra-file only.
- **Method call resolution is approximate.** A call's `callee_path` is matched to
  an in-file function by its last segment (`obj.run` → `run`), so a tainted value
  passed to a *non-self positional parameter* of a method (`obj.m(t)` where `t`
  binds the second formal) can be missed because the receiver shifts the argument
  indices — a false negative, P5-safe. A same-named top-level function may also be
  applied (a false positive — acceptable noise). Tainted *receivers* (`self`)
  resolve correctly.
- **Alias through mutation** (`a = b; b.x = t; a.x` …), **dynamic subscripts**,
  and **dynamic / `*` imports** are best-effort or out of scope; taint is tracked
  per access path, not per heap object.
- **Implicit / control-dependence flows** (tainting via a branch condition) are
  out of scope.
- **`when: {keyword: …}` is literal-equality only** — `shell=<truthy variable>`
  is a false negative.
- **`args` is positional-only** — a dangerous value passed by keyword is not
  covered by a positional `args` restriction (model such sinks with `when`).
- **External-callee fallback** over-taints benign wrappers (FP-biased) by design;
  add a DSL propagator/sanitizer to refine.

The one-sidedness guarantee covers **sanitizers** (a missing sanitizer is noise, a
false positive — never a silently-suppressed real vulnerability), not overall
soundness.
