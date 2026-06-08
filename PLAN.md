# scanipy OSS — v1 implementation plan ("make the tool actually work")

> **What this is.** The build plan that turns the `0.1.0` scaffold into a working,
> tested, documented `0.2.0` taint-tracking SAST CLI. It is the source of truth for
> the build; per-task detail lives in the task tables (§6) and the principles in
> `.claude/rules/principles.md` win on any conflict. Derived from a parallel design
> pass (1 prior-art researcher + 8 subsystem architects).

---

## 1. Goal, scope, decisions

**Goal:** `scanipy scan <path>` performs real taint analysis on Python code, follows
untrusted data from sources to sinks (through sanitizers), and reports each finding
with its `source → … → sink` witness — deterministically, locally, zero-config.

**Locked decisions (v1):**

| # | Decision |
|---|---|
| Engine depth | **Intraprocedural + intra-file interprocedural** via TITO function summaries. **No** cross-file/project-wide analysis. |
| Detector catalog | **Core 6**: os-command (CWE-78), sql (CWE-89), code-injection (CWE-94), path-traversal (CWE-22), ssrf (CWE-918), unsafe-deserialization (CWE-502). **+ up to 2 stretch**: xxe (CWE-611), tls-verify-disabled (CWE-295). |
| Merge flow | Dependency-ordered **PRs into protected `main`, auto-merged once CI is green** (one PR per component). |
| Definition of done | Working scan, full tests incl. per-detector TP/TN, docs/README/CHANGELOG updated, `__version__` → `0.2.0`, CI green on 3.10–3.13. **No PyPI publish.** |

**Out of scope for v1 (state honestly — P7):** cross-file/whole-program taint;
languages other than Python; implicit/control-dependence flows; full alias soundness
(taint is tracked per access-path, not per heap object); PyPI publication.

---

## 2. Architecture

A single, linear, **detector-agnostic** pipeline. Detection knowledge lives entirely
in the YAML DSL specs (P4); the engine only matches patterns and moves taint labels.

```
discovery → frontend(AST→IR) → [per file] taint engine ─uses→ matcher(DSL Pattern ↔ IR)
                                      │                              ↑
                                      │            registry → parse_spec → DetectorSpec pack
                                      ▼
                          findings (witness-backed) → aggregate/filter/sort/dedup
                                      ▼
                          reporter (text/json/sarif) → stdout/-o → exit code
```

**Load-bearing design choices (grounded in PyT / Semgrep taint-mode / Pysa TITO; see
`docs/design/` archive):**

- **Import/alias canonicalization is a first-class, pre-matching step.** Every
  `Name`/`Attribute` is resolved to a canonical dotted path via a per-module import
  table so `import os; os.system`, `from os import system; system`, `import os as o;
  o.system`, and `import os.path as p; p.join` all match the dotted DSL patterns.
  Skipping this causes silent false negatives.
- **Taint env keyed by access paths** (base var + bounded `.attr`/const-subscript
  suffix, **depth cap 2–3**). At the cap, **over-approximate** (collapse to the prefix,
  may taint siblings) — biases to false positives, never false negatives (P5-safe).
- **Flow-sensitive forward dataflow over a per-function CFG.** Transfer per statement:
  sources **add** labels; assignments **kill then reassign** the LHS path; propagators
  **move** taint per `from→to`; sanitizers **remove** the label on the path where they
  definitely run. **Joins union, never intersect** (sanitized in one branch only ⇒
  still tainted) — the load-bearing P5 rule. Loops iterate a **bounded fixpoint**.
- **Intra-file interprocedural via TITO function summaries**, not inlining. Build the
  in-file call graph, condense SCCs, compute summaries in reverse-topological order;
  recursion via a bounded worklist fixpoint. A summary is a sorted set of transfer
  flows (`param_i→return`, `param_i→sink S`, `source→return`, …), each carrying a
  compact sub-trace for **witness splicing** at call sites. Formal params are handled
  as engine-internal symbolic taint — **no DSL change required** for interprocedural.
- **Witness-backed findings (P2):** every finding carries the ordered
  `WitnessStep` chain; interprocedural hits splice the callee fragment in.
- **Determinism (P3):** total order on findings — primary `(file, line, col,
  detector_id)`, final tie-break on a **witness fingerprint** (sha256 of the ordered
  `(role, file, line, col)` tuples). Witness selection: shortest path, then
  lexicographically smallest locations. All spec/source/sink/worklist iteration sorted;
  never depend on dict/set/filesystem order.

**Documented unsoundness (P7, ship in `docs/ir-reference.md` + `docs/dsl-reference.md`):**
alias-through-mutation, dynamic subscripts, dynamic/`*` imports, and implicit flows are
best-effort or out of scope. P5's one-sidedness covers **sanitizers**, not overall
soundness.

---

## 3. Canonical module layout — RESOLVED (build agents MUST follow)

The parallel design produced two proposals each for "the IR" and "the matcher". These
are the binding decisions; ignore the per-component file names where they differ.

```
src/scanipy/
  ir.py                 # NEW — the ONE shared normalized IR (frontend produces; engine + matcher consume).
                        #       Resolves frontends/ir.py vs engine/ir.py: neutral top-level module, no import cycle.
  frontends/
    base.py             # EDIT — Frontend.parse(path) -> ir.IRModule | None
    resolver.py         # NEW  — import/alias table + canonical_dotted()
    python_frontend.py  # REWRITE — ast -> ir.IRModule; return None on SyntaxError/decode/OS error
  engine/
    matcher.py          # NEW — the ONE matcher: match(Pattern, node) -> MatchResult|None  (consolidates matcher.py/matching.py)
    taint_state.py      # NEW — access-path taint lattice
    propagation.py      # NEW — generic built-in + DSL propagators
    witness.py          # NEW — witness build / select / fingerprint
    summaries.py        # NEW — TITO summaries, fixpoint, call-site application + splicing
    taint.py            # IMPLEMENT — TaintEngine.analyze orchestrates the above
  dsl/parser.py         # IMPLEMENT — parse_spec + DSLError (location-aware)
  registry.py           # IMPLEMENT — load_builtin_detectors()
  config.py             # IMPLEMENT — layered config (.scanipy.yml + [tool.scanipy])
  discovery.py          # NEW — file walk + excludes + .gitignore
  scanner.py            # NEW — orchestrator (discover→parse→analyze→aggregate→report→exit)
  cli.py                # REWRITE scan + rules (thin; delegates to scanner)
  reporting/            # EXISTS — enforce SARIF sort_keys determinism
  detectors/<class>/<name>.yml   # catalog (data only, P4)
docs/   ir-reference.md(NEW) testing.md(NEW) examples/end-to-end.md(NEW)
        dsl-reference.md/usage.md/writing-detectors.md (UPDATE)
tests/  unit/ integration/ fixtures/ _support/
```

---

## 4. Work packages (one PR each)

| WP | Component | Owns | Depends on |
|---|---|---|---|
| **A** | DSL parser & registry | `dsl/parser.py`, `registry.load_builtin_detectors` | (scaffold types) |
| **B** | Python frontend & IR | `ir.py`, `frontends/{resolver,python_frontend,base}.py` | (scaffold types) |
| **C** | Pattern matcher | `engine/matcher.py` | B (ir) |
| **D** | Taint engine | `engine/{taint,taint_state,propagation,witness,summaries}.py` | A, B, C |
| **E** | Detector catalog | `detectors/**/*.yml`, `tests/fixtures/**` | A, B, D |
| **F** | CLI / scan pipeline | `scanner.py`, `discovery.py`, `config.py`, `cli.py`, `reporting/*` | A, B, D |
| **G** | Testing & QA (cross-cutting) | `tests/integration/**`, `tests/_support/**`, coverage gate | D, E, F |
| **H** | Docs / changelog / version | `README.md`, `docs/**`, `CHANGELOG.md`, `__version__` | all |

---

## 5. Dependency DAG & phase plan

```
Phase 0  baseline:  merge scaffold PR #1 → main
Phase 1  ║ A DSL parser ║ B frontend+IR ║         (independent, parallel)
Phase 2  C matcher                                  (needs B)
Phase 3  D taint engine                             (needs A,B,C)
Phase 4  ║ E detector catalog ║ F CLI pipeline ║    (need A,B,D; disjoint files, parallel)
Phase 5  G testing & QA (cross-cutting)             (needs D,E,F)
Phase 6  H docs / version 0.2.0 / changelog         (needs all)
```

Rules: a phase's PRs merge into `main` (auto, once CI green) before the next phase
branches off; **parallel PRs within a phase must touch disjoint files**; each PR is
self-contained and CI-green on its own.

---

## 6. Work breakdown (102 tasks)

Sizes: S ≈ <100 LOC, M ≈ 100–300, L ≈ 300+. `⇐` = depends-on.

### WP-A — DSL parser & registry (PR `feat/dsl-parser`)
- S `DSL_PARSER_1` DSLError carries spec id + field + source location
- M `DSL_PARSER_2` YAML node-tree loader w/ location tracking ⇐ 1
- M `DSL_PARSER_3` Top-level field validation (required/optional/unknown/enums) ⇐ 2
- L `DSL_PARSER_4` Pattern parsing + dotted/wildcard grammar + args + when ⇐ 3
- M `DSL_PARSER_5` Implement `parameter` & `import` kinds (lift from PLANNED) ⇐ 4
- M `DSL_PARSER_6` Propagator parsing + flow vocabulary ⇐ 4
- M `DSL_PARSER_7` Assemble + return DetectorSpec; finalize parse_spec ⇐ 3,4,5,6
- S `DSL_PARSER_8` Wire `registry.load_builtin_detectors` ⇐ 7
- S `DSL_PARSER_9` Validate bundled specs parse + reconcile DSL surface ⇐ 8
- L `DSL_PARSER_10` Tests: happy-path + every rejection + locations ⇐ 7
- M `DSL_PARSER_11` Tests: registry loader + bundled-pack invariants ⇐ 8
- S `DSL_PARSER_12` Docs: dsl-reference + CHANGELOG for parser ⇐ 5,7

### WP-B — Python frontend & IR (PR `feat/frontend-ir`)
- M `FRONTEND_IR_1` Define IR dataclasses (`ir.py`)
- M `FRONTEND_IR_2` Import/alias resolution (`resolver.py`) ⇐ 1
- L `FRONTEND_IR_3` Expression lowering (ast.expr → Expr) ⇐ 1,2
- M `FRONTEND_IR_4` Binder/target lowering (full inventory) ⇐ 1,3
- L `FRONTEND_IR_5` Statement lowering + minimal CFG builder ⇐ 1,3,4
- M `FRONTEND_IR_6` Scope/function table + module-as-scope ⇐ 2,4,5
- S `FRONTEND_IR_7` `PythonFrontend.parse` wiring + graceful errors ⇐ 6
- S `FRONTEND_IR_8` IR contract docs (`docs/ir-reference.md`) ⇐ 7
- M `FRONTEND_IR_9` Frontend/IR unit tests ⇐ 7

### WP-C — Pattern matcher (PR `feat/matcher`)
- S `MATCHER_1` ResolvedNode / KeywordValue protocols (consume `ir.py`)
- M `MATCHER_2` Segment-wise wildcard matcher `_match_dotted`
- S `MATCHER_3` `_resolve_arg_indices` (positional, receiver-excluded)
- M `MATCHER_4` `_match_when` (keyword literal-equality, AND, sorted) ⇐ 1
- M `MATCHER_5` Public `match()` + `MatchResult` ⇐ 1,2,3,4
- S `MATCHER_6` Export matcher API from `engine/__init__.py` ⇐ 5
- M `MATCHER_7` Tests with fake ResolvedNodes ⇐ 5
- S `MATCHER_8` Pin wildcard + constraint semantics in dsl-reference ⇐ 5
- S `MATCHER_9` Confirm parser validates args/when shape & placement ⇐ 2,4

### WP-D — Taint engine (PR `feat/taint-engine`)
- M `ENGINE_1` IR-consumption contract assertions (uses `ir.py`)
- M `ENGINE_2` Pattern matching glue (uses `matcher.py`) ⇐ 1
- L `ENGINE_3` Taint state lattice (`taint_state.py`) ⇐ 1
- M `ENGINE_4` Witness construction, selection, fingerprints (`witness.py`) ⇐ 1
- L `ENGINE_5` Generic built-in propagation (`propagation.py`) ⇐ 2,3,4
- L `ENGINE_6` Intraprocedural CFG dataflow + seeding + sink emission ⇐ 5
- L `ENGINE_7` Function summaries to fixpoint over call graph (`summaries.py`) ⇐ 6
- M `ENGINE_8` Summary application + witness splicing at call sites ⇐ 7
- M `ENGINE_9` Wire `TaintEngine.analyze`: phases, dedup, sort, fingerprints ⇐ 6,8
- M `ENGINE_10` Unit tests: matching ⇐ 2
- L `ENGINE_11` Unit tests: intraprocedural TP/TN (hand-built IR) ⇐ 6
- L `ENGINE_12` Unit tests: interprocedural summaries + splicing + recursion ⇐ 7,8
- M `ENGINE_13` Unit tests: determinism + fingerprints ⇐ 9
- M `ENGINE_14` End-to-end integration over real fixtures ⇐ 9
- M `ENGINE_15` Docs: engine + DSL semantics + honest scope ⇐ 9

### WP-E — Detector catalog + fixtures (PR `feat/detectors`)
- S `DETECTOR_1` Validate existing os-command & sql specs vs finished schema ⇐ A
- S `DETECTOR_2` Author sql TP/TN fixtures (missing today)
- M `DETECTOR_3` code-injection spec (CWE-94, critical) + TP/TN
- M `DETECTOR_4` path-traversal spec (CWE-22, high) + TP/TN
- M `DETECTOR_5` ssrf spec (CWE-918, high) + TP/TN
- M `DETECTOR_6` unsafe-deserialization spec (CWE-502, critical) + TP/TN
- M `DETECTOR_7` xxe stretch spec (CWE-611, high) + TP/TN
- M `DETECTOR_8` tls-verify-disabled stretch (CWE-295) — **gated** on engine presence-sink; else defer
- M `DETECTOR_9` Interprocedural TP/TN fixtures (exercise summaries)
- L `DETECTOR_10` Per-detector TP/TN integration matrix ⇐ 1–7,9 + A,B,D
- S `DETECTOR_11` dsl-reference: v1 known-limitations + forced DSL extensions ⇐ A,D
- S `DETECTOR_12` Wire catalog into rules list/show, scan; CHANGELOG ⇐ 10,11

### WP-F — CLI / scan pipeline / config / discovery (PR `feat/scan-pipeline`)
- M `CLI_1` Config loader: `.scanipy.yml` + `[tool.scanipy]` discovery & validation
- S `CLI_2` Config merge: CLI > file > defaults (click param-source) ⇐ 1
- M `CLI_3` File discovery: default + glob excludes, deterministic order
- M `CLI_4` `.gitignore` honoring (stdlib-only, default-on, `--no-gitignore`) ⇐ 3
- S `CLI_5` Registry: `load_builtin_detectors` + `load_detector_specs(selected)` ⇐ A
- M `CLI_6` Orchestrator `scanner.run_scan` + per-file isolation ⇐ 3,5,B,D
- M `CLI_7` Aggregation: severity filter, deterministic dedup, total-order sort ⇐ 6
- S `CLI_8` Exit-code computation ⇐ 7
- M `CLI_9` Wire `scan` command (thin) ⇐ 2,8
- M `CLI_10` Implement `rules list/show/validate` ⇐ 5
- L `CLI_11` Tests: config, discovery, scanner, exit codes, CLI, e2e ⇐ 9,10
- M `CLI_12` Docs + CHANGELOG ⇐ 11

### WP-G — Testing & QA, cross-cutting (PR `test/qa-suite`)
- S `QA_1` Test-support: fixture pairing index ⇐ A
- S `QA_2` Output normalizers (version + path tolerant)
- M `QA_3` Extend conftest: corpus + parametrize hook ⇐ 1,F
- M `QA_4` DSL parser unit tests (pos/neg/purity) ⇐ A · L `QA_5` Frontend/IR tests + resilience ⇐ B
- M `QA_6` Matcher unit tests ⇐ C · L `QA_7` Engine transfer-function tests ⇐ D
- L `QA_8` Interprocedural summary tests ⇐ D · S `QA_9` Config tests ⇐ F
- M `QA_10` Scanner orchestration tests ⇐ F · S `QA_11` Reporter determinism / SARIF sort_keys ⇐ F
- S `QA_12` Registry parse-all + self-validation ⇐ A
- M `QA_13` End-to-end exact-findings integration ⇐ D,F,A
- M `QA_14` **P5 catalog enforcement matrix** (auto-parametrized from fixtures) ⇐ 3,E
- S `QA_15` Determinism integration (P3) ⇐ 2,F · M `QA_16` Golden json+sarif snapshots ⇐ 2,F,E
- M `QA_17` Unparsable/binary-file resilience ⇐ F,5 · S `QA_18` Performance smoke ⇐ F,D
- M `QA_19` CLI scan/rules integration (CliRunner) ⇐ F · S `QA_20` Migrate stub-asserting CLI tests ⇐ F,19
- S `QA_21` Coverage gate (`--cov-fail-under=90`) + CI wiring ⇐ 13,14
- S `QA_22` `docs/testing.md` ⇐ 16,21

### WP-H — Docs / changelog / version / release readiness (PR `docs/v0.2.0`)
- S `DOCS_1` Bump `__version__` → 0.2.0
- M `DOCS_2` De-stub README ⇐ E,F · M `DOCS_3` De-stub docs/usage.md ⇐ F,7
- M `DOCS_4` Finalize/lock dsl-reference (promote parameter/import) ⇐ A,D
- M `DOCS_5` Refresh writing-detectors.md ⇐ 4,E
- M `DOCS_6` CHANGELOG 0.2.0 section ⇐ 1,E
- M `DOCS_7` Verified end-to-end example (`docs/examples/end-to-end.md`) ⇐ F,D,1
- S `DOCS_8` Release-readiness checklist (NO publish) ⇐ 1,6
- S `DOCS_TEST_1` Version+changelog consistency test ⇐ 1,2,3,6
- M `DOCS_TEST_2` End-to-end example matches real CLI output ⇐ 7
- M `DOCS_TEST_3` Docs reflect real catalog (bijection) ⇐ 4,6,E,A

---

## 7. Commit & PR strategy

- **One PR per work package**, branch `feat/<wp>` (or `test/`, `docs/`), into `main`.
- Each PR: SPDX headers, conventional-commit title, **CI-green standing alone** (ruff,
  ruff format, mypy --strict, pytest on 3.10–3.13), and the `protect-main` ruleset's
  required checks satisfied → **auto-merged** by the orchestrator.
- Dependency-ordered: a phase's PRs merge before the next phase branches off `main`.
- Parallel PRs within a phase touch **disjoint files**; the orchestrator sequences
  merges and rebases on the rare conflict.
- Commits within a PR map to tasks (e.g. `feat(engine): intraprocedural CFG dataflow (ENGINE_6)`).

---

## 8. Acceptance gates (per phase) & global Definition of Done

- **A green:** `parse_spec` validates all forms with location-aware `DSLError`; bundled
  specs parse; `load_builtin_detectors` returns sorted, unique, ≥1 source/≥1 sink each.
- **B green:** four import styles canonicalize identically; value-rooted chains
  (`conn.cursor.execute`) preserved; full binder inventory; parse returns `None` (never
  raises) on bad files; CFG with union-joins emitted; zero detector vocabulary in
  `frontends/`.
- **C green:** pure matcher; exact/trailing-single/leading-greedy wildcard semantics;
  `args`/`when` honored; never widens on unknowns.
- **D green:** `TaintEngine.analyze` returns findings; **zero per-CWE branching**
  (grep-verified); os-command TP flagged / TN silent; SQL bound-params not flagged;
  one-sided sanitizers (union-at-join); interprocedural splice works; recursion
  terminates; byte-identical across runs and spec-order shuffles; stable fingerprints.
- **E green:** 6 core (+shipped stretch) specs parse and use only the frozen DSL; every
  detector has TP+TN fixtures; per-detector matrix passes; tls-verify shipped-or-deferred
  honestly.
- **F green:** `scanipy scan <vuln>` exits 1 with witness; `<safe>` exits 0; zero-config
  works; no network; deterministic stdout for text/json/sarif; excludes + gitignore;
  config precedence CLI>file>defaults; `rules list/show/validate` work; thin cli.py.
- **G green:** P5 matrix auto-parametrized from fixtures; determinism (byte-identical
  json+sarif); golden snapshots; unparsable-file resilience; perf smoke bounded;
  hermetic (no network/subprocess); **coverage ≥ 90%**.
- **H green:** `__version__ == 0.2.0`; README/usage de-stubbed and honest that it's
  install-from-source (not on PyPI); dsl-reference locked; CHANGELOG 0.2.0; verified
  end-to-end example; docs↔catalog bijection enforced by test.

**Global DoD:** all eight PRs merged to `main`; CI green on 3.10–3.13; the working
`scanipy scan` demonstrated on the fixture corpus; **no PyPI publish** (release-readiness
checklist ends with an explicit STOP).

---

## 9. Risk register (top risks → mitigation)

| Risk | Mitigation |
|---|---|
| Import/alias resolution missed ⇒ silent FNs | First-class canonicalization step (WP-B); integration test over all 4 import styles. |
| Determinism regressions (collisions, set order) | Total order + witness-fingerprint tie-break; sorted iteration everywhere; scan-twice byte-identical test (WP-G). |
| Join semantics wrong (intersection) ⇒ missed vulns | Union-at-join is an explicit acceptance test (sanitized-in-one-branch still flagged). |
| Recursion / large SCC blowup | Bounded fixpoint iteration cap + access-path depth cap + summary memoization; perf smoke. |
| DSL must grow (kwarg args, by-side-effect flow) | Centralized grammar constants; extend DSL not engine (P4); record in dsl-reference. |
| IR/matcher file-name divergence between agents | **§3 resolves it** — `ir.py` + `engine/matcher.py` are binding. |
| tls-verify needs a non-taint "presence sink" | Treat as stretch; ship only if engine adds presence-sink, else defer honestly. |
| Over-tainting from depth-cap collapse ⇒ FPs | Accepted, P5-safe; documented; tune caps if noisy. |

---

## 10. Orchestration plan (how the build runs)

Executed as **one Workflow per phase**; I drive merges from the main loop.

1. **Phase 0:** merge scaffold PR #1 → `main` (CI-green baseline).
2. **Per phase:** a Workflow fans out **one implementation agent per WP in that phase**,
   each in an **isolated git worktree** (`isolation: worktree`) on its `feat/<wp>` branch.
   Each agent: reads this PLAN + its task table + the design archive, implements every
   task, runs the local gate (`ruff` / `ruff format --check` / `mypy src` / `pytest`),
   and commits. A second workflow stage runs an **adversarial reviewer** per WP
   (principles + acceptance criteria) before the PR is opened.
3. I push each branch, open its PR, wait for required CI checks to go green, and
   **auto-merge** (admin) in dependency order; then the next phase branches off the
   updated `main`.
4. After Phase 6: final full-suite verification on `main`, then STOP (no publish) and
   report. `docs/release-readiness.md` is the human checklist for an eventual release.

Estimated fan-out: ~8 implementation agents (+ reviewers) across phases 1–6, plus the
already-spent 9 design agents. Large components (engine, testing) may split into two
stacked PRs if a single PR would be unwieldy.

---

## 11. Definition of done (v1 / 0.2.0)

- [ ] WP-A…H merged to `main` via auto-merged, CI-green PRs.
- [ ] `scanipy scan` works end-to-end; 6 core detectors flag TP / clear TN (P5).
- [ ] Intra-file interprocedural taint with spliced witnesses; deterministic output (P3).
- [ ] Engine has zero per-CWE logic (P4, grep-verified); no network on scan path (P1).
- [ ] Tests green on 3.10–3.13; coverage ≥ 90%; golden snapshots; P5 matrix.
- [ ] README/docs de-stubbed and honest (P7); `__version__ = 0.2.0`; CHANGELOG updated.
- [ ] Release-readiness checklist complete — **no publish performed.**
