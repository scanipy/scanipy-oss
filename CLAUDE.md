# CLAUDE.md — scanipy (open-source edition)

Agent context for this repository. Read it fully at session start. It is the
lean operating guide; deeper material lives in `docs/` and `.claude/`.

---

## 1. What this is

**scanipy** (OSS) is a local, private, taint-tracking SAST **CLI** for Python.
It follows untrusted data from a **source** through your code to a dangerous
**sink** (unless a **sanitizer** intervenes) and reports the **witness** —
the `source → … → sink` data-flow trace — behind every finding. Detection logic
is declarative YAML (the taint DSL); the engine is class-agnostic.

This is the free, open-source taste of the commercial **scanipy Cloud** platform.
Keep the scopes honest (principle **P7**): the OSS tool is single-language and
intraprocedural-leaning. It does **not** claim the platform's interprocedural,
multi-tenant, or attested-determinism guarantees. Never copy the proprietary
IFDS/IDE engine internals into this repo — the OSS DSL is its own, simpler design.

- **Distribution (PyPI):** `scanipy-oss`  ·  **import package & command:** `scanipy`
- **Python:** ≥ 3.10  ·  **License:** Apache-2.0  ·  **Version:** 0.2.0

## 2. Status — working tool (0.2.0)

`scanipy scan` works end-to-end: the Python frontend builds an IR, the taint
engine tracks data flow (intraprocedural **+ intra-file interprocedural** via
function summaries), and detectors are declarative DSL specs. All commands are real.

| Works (0.2.0) | Notes |
|---|---|
| `scanipy scan PATH` | taint analysis → witness-backed findings; `--format text\|json\|sarif`; exit `0`/`1`/`2` |
| `scanipy rules list/show/validate` | inspect/validate the detector catalog |
| `scanipy version`, `--help`, `--version` | — |
| 7 detectors | os-command, sql, code-injection, path-traversal, ssrf, unsafe-deserialization, xxe |
| Engine | `dsl.parse_spec`, `frontends.PythonFrontend.parse`, `engine.TaintEngine.analyze` all implemented |

Built per **[PLAN.md](PLAN.md)** (architecture, work breakdown, phase plan);
per-subsystem design notes in [docs/design/v1-design-notes.md](docs/design/v1-design-notes.md).
Honest scope (**P7**): single-language (Python), intraprocedural **+ intra-file
interprocedural** only; documented limitations live in `docs/dsl-reference.md` and
`docs/ir-reference.md`. Not yet on PyPI — install from source (`pip install -e .`).

## 3. Repository map

```
src/scanipy/
  cli.py            CLI (click) — commands, flags, exit codes
  exit_codes.py     ExitCode: OK=0, FINDINGS=1, ERROR=2
  models.py         Severity, Location, WitnessStep, Finding (carries the witness)
  config.py         ScanConfig + load_config (defaults only for now)
  registry.py       discovers bundled detector specs
  dsl/              taint DSL (draft/v0): patterns.py, spec.py, parser.py
  engine/taint.py   TaintEngine (stub)
  frontends/        Frontend ABC + python_frontend.py (ast-based, stub)
  reporting/        text / json / sarif reporters (functional)
  detectors/<class>/<name>.yml   bundled detector specs (package data)
tests/
  unit/             pytest suites (CLI smoke + core)
  fixtures/python/{vulnerable,safe}/   true-positive / true-negative corpora
docs/
  usage.md  writing-detectors.md  dsl-reference.md   (dsl-reference = canonical schema)
.claude/
  agents/  commands/  rules/  settings.json
.github/workflows/  ci.yml  release.yml
pyproject.toml  (hatchling, ruff, mypy, pytest config)
```

## 4. The taint model and the DSL

A detector is a YAML spec with `sources`, `sinks`, `sanitizers`, and
`propagators` (pattern `kind` ∈ `call`, `attribute`, `parameter`, `import`;
dotted patterns with `*` wildcards). The DSL is **draft/v0** and co-evolves with
the engine.

**The canonical, field-by-field schema lives in `docs/dsl-reference.md`.** Do not
restate the full schema elsewhere — link to it.

## 5. Principles (the load-bearing invariants)

| | Principle | Means |
|---|---|---|
| **P1** | Local & private | A scan never sends source code over the network. No telemetry of code. |
| **P2** | Witness-backed | Every `Finding` carries its `source → … → sink` trace. |
| **P3** | Deterministic | Same code + same detector-pack version ⇒ identical findings (sorted, stable output). |
| **P4** | Declarative detectors | Detection logic lives in DSL specs, never hard-coded in engine code. |
| **P5** | TP **and** TN fixtures | Every detector ships a vulnerable fixture it must flag and a safe one it must not. Sanitizer soundness is **one-sided**: a missing sanitizer is a false positive (noise), never a silently-suppressed real vuln. |
| **P6** | Zero-config | Built-in detectors run with no setup; minimal dependencies. |
| **P7** | Honest scope | Don't overclaim vs. the SaaS; mark unfinished things as unfinished. |

Full text with examples: `.claude/rules/principles.md`.

## 6. Developer workflow

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install

ruff check . && ruff format --check .   # lint + format
mypy src                                # strict types
pytest                                  # tests
```

## 7. Conventions

- **SPDX header** on every Python file: `# SPDX-License-Identifier: Apache-2.0`.
- **ruff** (line-length 100, double quotes) and **mypy strict** must stay green.
- Full type hints on all new code.
- `tests/fixtures/` holds intentionally-vulnerable sample programs — it is
  analysis DATA, excluded from ruff/mypy. Never "fix" a fixture.
- Detector ids: `<language>.<class>.<name>` (e.g. `python.injection.os-command`).
- **Conventional Commits** for messages and PR titles.

## 8. Agent team and commands

Definitions live in `.claude/`. Each agent owns a slice and upholds the principles.

| Agent (`.claude/agents/`) | Owns | Key principles |
|---|---|---|
| `taint-engine` | `engine/`, `frontends/`, `dsl/parser.py` | P2, P3, P4, P7 |
| `detector-author` | `detectors/**/*.yml`, `tests/fixtures/**` | P4, P5 |
| `cli-ux` | `cli.py`, `config.py`, `reporting/` | P1, P6 |
| `qa-test` | `tests/` | P3, P5 |
| `docs-writer` | `README.md`, `docs/` | P7 |
| `release-eng` | `pyproject.toml`, `.github/`, `CHANGELOG.md` | P3 |
| `code-reviewer` | reviews diffs (no writes) | P1–P7 |

Helper commands (`.claude/commands/`): `/new-detector`, `/scan-self`, `/release`.

## 9. Definition of done (any change)

1. `ruff check .` and `ruff format --check .` clean.
2. `mypy src` clean (strict).
3. `pytest` green.
4. New/changed behavior has tests.
5. **New detector ⇒ both a TP and a TN fixture** (P5) and the spec validates.
6. SPDX header on new Python files; docs updated if behavior changed.
7. The change does not overclaim scope (P7) or break a principle (P1–P6).
