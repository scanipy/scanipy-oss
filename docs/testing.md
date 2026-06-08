<!-- SPDX-License-Identifier: Apache-2.0 -->
# Testing & QA

scanipy's test suite is a layered set of fast, hermetic pytest modules plus a
handful of **cross-cutting enforcement suites** that encode the project's
load-bearing guarantees: deterministic output (P3), one-sided sanitizer
soundness (P5), local-and-private operation (P1), and honest, graceful handling
of bad inputs (P7). This document describes how the suite is organized, how to
run it, and how to maintain the golden snapshots and the coverage gate.

## Running the tests

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

ruff check . && ruff format --check .          # lint + format
mypy src                                        # strict types (package source)
pytest --cov=scanipy --cov-fail-under=90        # tests + coverage gate
```

Tests are tagged with two markers (registered in `pyproject.toml`):

| Marker | Meaning | Select with |
|---|---|---|
| `unit` | fast, isolated component tests (no filesystem walks beyond `tmp_path`) | `pytest -m unit` |
| `integration` | the wired pipeline (registry → scanner → frontend → engine → reporter, and the CLI via `CliRunner`) over real fixtures | `pytest -m integration` |

## Layout

```
tests/
  conftest.py                 shared fixtures (the CliRunner `runner`)
  _support/                   test-only helper package (SPDX-headed, stdlib + scanipy)
    normalize.py              version/path/fingerprint-tolerant report normalizers
    corpus.py                 the shared scan corpus + run_corpus_scan entry point
  unit/                       one module per component (parser, frontend/IR, matcher,
                              engine transfer functions, summaries, lattice, config,
                              scanner, reporters, registry, CLI)
  integration/
    test_detectors.py         the P5 catalog matrix (auto-parametrized per detector)
    test_engine_end_to_end.py exact-finding end-to-end checks
    test_cli.py               CLI scan/rules via CliRunner
    test_determinism.py       P3: scan-twice byte-identical + input-order invariance
    test_golden_reports.py    committed, normalized JSON + SARIF snapshots
    test_resilience.py        SyntaxError + non-UTF-8 files → skipped, not fatal
    test_performance_smoke.py ~50 synthetic files (deep chains + recursion), bounded
    test_hermeticity.py       no-network socket guard + no-subprocess meta-test
  fixtures/                   analysis DATA (intentionally-vulnerable code), lint-excluded
  golden/                     committed normalized snapshots (scan-corpus.json,
                              scan-corpus.sarif.json)
```

`tests/_support/` is intentionally tiny and dependency-free so every cross-cutting
suite reuses one definition of "the corpus" and one set of normalizers (DRY,
determinism).

## The P5 catalog matrix

`tests/integration/test_detectors.py` is auto-parametrized over the bundled
detector catalog: for every detector it scans the paired true-positive fixture
(`tests/fixtures/python/vulnerable/<stem>.py`, which it must flag) and the paired
true-negative fixture (`tests/fixtures/python/safe/<stem>.py`, which it must not).
Adding a detector YAML plus its TP/TN fixtures extends the matrix with **zero**
engine or test edits (P4). The safe fixtures route the *same* tainted value into
the safe form (bound parameters, `shlex.quote`, `ast.literal_eval`,
`yaml.safe_load`, `defusedxml`, …) so the test discriminates sink/sanitizer
behavior, not mere absence of taint — preserving the one-sidedness of P5 (a
missing sanitizer is noise, never a silently-suppressed real vulnerability).

## Determinism (P3)

`tests/integration/test_determinism.py` asserts the user-visible guarantees:

- scanning the corpus twice yields **byte-identical JSON**, and **byte-identical
  SARIF**; and
- the order in which input files are fed to the engine does not change the final
  sorted finding set (the total order is real, not an artifact of discovery's
  internal sort).

The engine-internal determinism (repeated single-file analysis, spec-order
shuffling, the witness-fingerprint tie-break, golden fingerprint values) is
covered by the engine unit suites.

## Golden snapshots

`tests/integration/test_golden_reports.py` scans the fixed corpus (the
`vulnerable/` + `safe/` fixture trees), renders JSON and SARIF, **normalizes**
the output, and compares it to the snapshots committed under `tests/golden/`.

Normalization (`tests/_support/normalize.py`) makes the snapshots stable across
machines and version bumps by rewriting three machine/version-dependent things:

| Normalized | Why |
|---|---|
| the embedded tool version → `"<VERSION>"` | both reporters embed `scanipy.__version__`, and the release bumps it |
| absolute file paths → repo-relative POSIX (`corpus/...`) | scans run under a per-test `tmp_path` |
| the witness `fingerprint` → `"<FINGERPRINT>"` | the fingerprint is a sha256 of the witness `(role, file, line, col)` tuples — deterministic **for a given path** (asserted directly in the determinism suite) but path-dependent by construction, so it cannot appear verbatim in a machine-independent golden |

Because the goldens are normalized **on disk**, they never contain a machine path
or the version string, so a version bump or a different CI runner does not break
them — while a real change to the findings still does.

### Regenerating goldens

After an *intentional* change to the catalog, engine, or report shape:

```bash
SCANIPY_UPDATE_GOLDEN=1 pytest tests/integration/test_golden_reports.py
```

This rewrites `tests/golden/scan-corpus.json` and `scan-corpus.sarif.json` from
the current (normalized) output and skips the comparison for that run. Review the
diff and commit it deliberately — an unreviewed golden update defeats the purpose.

> The SARIF golden is stored as `scan-corpus.sarif.json` (SARIF *is* JSON) so the
> repo-wide `*.sarif` gitignore — which keeps transient scan output out of the
> tree — does not accidentally exclude this committed test artifact.

## Resilience (P7)

`tests/integration/test_resilience.py` scans a tree mixing valid code with a
Python `SyntaxError` file and a non-UTF-8 / binary `.py` file. The scan must
complete, still scan and flag the valid files, and record the bad files as
**skipped diagnostics** (`ScanResult.parse_errors`) rather than raising. The CLI
returns OK/FINDINGS — *not* ERROR — for unparsable inputs; a genuinely missing
path is the one case that is a usage ERROR (exit 2).

## Performance smoke

`tests/integration/test_performance_smoke.py` generates ~50 synthetic files that
exercise the analysis features most prone to blowup — deep attribute chains and
(mutual) recursion that drive the summary fixpoint — and asserts the full scan
finishes under a *generous* wall-clock budget and produces a *deterministic*
finding count. It is not a benchmark; its job is to catch an accidental loss of a
depth / fixpoint cap (which turns the analysis quadratic-to-exponential).

## Hermeticity (P1)

`tests/integration/test_hermeticity.py` enforces three properties:

- **No network on the scan path.** A full corpus scan runs under a `socket`
  monkeypatch that makes any socket use raise; the scan still completes and flags
  the SSRF detector whose patterns *name* network calls. scanipy reads files from
  disk and analyzes in-process — it never opens a socket.
- **No subprocess in the suite.** The CLI is driven exclusively through
  `click.testing.CliRunner` (in-process). An AST meta-test asserts that no test
  module imports `subprocess` (fixtures are analysis DATA and are excluded).
- **I/O confinement.** Cross-cutting scans target a copied corpus under
  `tmp_path` only; they never touch the developer's working tree.

## Coverage policy

The global coverage gate is **90%** (line + branch over `src/scanipy`), enforced
in two places that must agree:

- `pyproject.toml` → `[tool.coverage.report] fail_under = 90` (so local runs match
  CI), and
- `.github/workflows/ci.yml` → `pytest … --cov-fail-under=90` on every entry of
  the Python 3.10–3.13 matrix.

Coverage tests **product behavior**; source is never modified to game a metric.
When a line is uncovered, the fix is a behavior test that reaches it (or an
honest `pragma: no cover` for genuinely unreachable defensive code — used
sparingly and only for interpreter-version-gated branches). The correctness-
critical core — the matcher, the taint lattice, and the engine transfer
functions — is targeted at or near 100%.
