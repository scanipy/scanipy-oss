# scanipy principles (P1–P7)

The load-bearing invariants. Every agent upholds them; the `code-reviewer` agent
checks them. They are summarized in `CLAUDE.md §5`; this file gives the why and a
counter-example for each.

---

## P1 — Local & private
A scan never sends source code over the network, and the tool emits no telemetry
of the code it analyzes. Privacy is a core trust promise of a security CLI.
- ✅ Read files from disk, analyze in-process, write results locally.
- ❌ POST a snapshot to an API; "phone home" with file contents; fetch remote
  rules at scan time without explicit opt-in.

## P2 — Witness-backed findings
Every `Finding` carries its `source → … → sink` data-flow trace as `WitnessStep`s.
The trace is the product: it shows *why* a finding is exploitable.
- ✅ `Finding(..., witness=(source_step, …, sink_step))`.
- ❌ Reporting "os.system used at line 10" with no path from an untrusted source.

## P3 — Determinism
Same code + same detector-pack version ⇒ identical output. CI diffs must be
meaningful.
- ✅ Sort findings by `(file, line, column, detector_id)`; `json.dumps(..., sort_keys=True)`.
- ❌ Output order that depends on `set`/`dict` iteration or `os.walk` order.

## P4 — Declarative detectors
Detection knowledge lives in the DSL specs (`detectors/**/*.yml`), never in
engine or CLI code. The engine is class-agnostic.
- ✅ Add a `source`/`sink` to a YAML spec; extend the DSL when it can't express a
  need (and update `docs/dsl-reference.md`).
- ❌ `if call == "os.system": report(...)` hard-coded in the engine.

## P5 — TP and TN fixtures (one-sided sanitizers)
Every detector ships a true-positive fixture it MUST flag and a true-negative
fixture it MUST NOT. Sanitizers are trusted in the **safe direction only**: a
missing sanitizer is noise (a false positive), never a silently-suppressed real
vulnerability.
- ✅ `vulnerable/x.py` (flagged) + `safe/x.py` (clean); omit a sanitizer when unsure.
- ❌ Shipping a spec with no safe fixture; marking something a sanitizer "to
  reduce noise" when it doesn't actually neutralize the taint.

## P6 — Zero-config
Built-in detectors run with no setup; dependencies stay minimal. `scanipy scan .`
works bare.
- ✅ Sensible defaults for every option.
- ❌ Requiring a config file or an external engine just to get a first result.

## P7 — Honest scope
The OSS tool is single-language and intraprocedural-leaning. Don't overclaim vs.
scanipy Cloud, and mark unfinished work as unfinished. Never copy the proprietary
IFDS/IDE internals into this repo.
- ✅ "scan is not implemented yet (exits 2)"; "OSS is local & single-language".
- ❌ Advertising interprocedural / multi-tenant / attested guarantees here.
