# Detector quality contract

Every detector spec under `src/scanipy/detectors/` must meet this bar. The
`detector-author` agent follows it; the `code-reviewer` agent enforces it. The
canonical field-by-field schema is `docs/dsl-reference.md` — this file is the
*quality* contract, not the schema.

## 1. Identity
- `id` follows `<language>.<class>.<name>` (e.g. `python.injection.os-command`).
- One vulnerability class per spec. Pick the most specific CWE.
- File lives at `src/scanipy/detectors/<class>/<name>.yml`.

## 2. Required content
- `id`, `name`, `cwe`, `severity`, `languages`, `message`, `sources`, `sinks`.
- `message` states **both** the flaw and the fix, in one or two sentences.
- Patterns use only the DSL `kind`s and constraints in `docs/dsl-reference.md`.

## 3. Fixtures (P5) — non-negotiable
- A **true-positive** fixture in `tests/fixtures/python/vulnerable/` that the
  detector must flag.
- A **true-negative** fixture in `tests/fixtures/python/safe/` (typically the
  sanitized version) that it must not flag.
- Fixtures are minimal, realistic, and self-contained.

## 4. Sanitizer soundness (one-sided)
- List something as a `sanitizer` only if it genuinely neutralizes the taint for
  that sink. When unsure, leave it out.
- A missing sanitizer ⇒ false positive (acceptable noise). A wrong sanitizer ⇒
  a missed real vulnerability (unacceptable). Err toward reporting.
- Remember some fixes are a different safe **sink** (e.g. bound SQL parameters),
  not a string sanitizer — model them accordingly.

## 5. Determinism (P3)
- No detector may introduce non-deterministic output. Findings are sorted
  centrally; specs must not rely on ordering.

## 6. Declarative only (P4)
- All detector behavior is expressed in the YAML. If you need engine support,
  request a DSL extension from the `taint-engine` agent — never special-case a
  detector in engine code.

## 7. Done
- `scanipy rules validate <file>` passes (once available).
- TP flagged, TN clean, `pytest` green, `ruff`/`mypy` green.
