# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0.0, anything MAY change between releases. Public
interfaces (the CLI surface and the taint DSL) are still settling, and breaking
changes can land in any minor release until 1.0.0.

## [Unreleased]

## [0.2.0] - 2026-06-09

**The taint engine works.** `scanipy scan` now performs real, deterministic,
local taint analysis: it follows untrusted data from sources to dangerous sinks
(through sanitizers and propagators) and reports the `source → … → sink` witness
behind every finding. The DSL parser, the Python frontend/IR, the matcher, the
taint engine, the detector catalog, and the `scan`/`rules` CLI are all
implemented. Scope is honest (P7): single-language (Python), intra-file
(including intra-file interprocedural via TITO function summaries) — no
cross-file / whole-program analysis. **Not yet published to PyPI** — install from
source for now (`pip install -e .`); `scanipy-oss` remains the reserved future
distribution name.

### Added

- **Working `scanipy scan PATH`** — real taint analysis with witness-backed,
  deterministic findings; zero-config; never sends code over the network (P1).
  Supports `--format text|json|sarif`, `--detectors`, `--severity-threshold`,
  `--fail-on`, `--exclude`, `--gitignore/--no-gitignore`, `--config`, and `-o`.
- **Working `scanipy rules list | show ID | validate FILE`** — list the bundled
  detectors (sorted by id, with CWE + severity), print one spec in full, and
  validate a spec against the DSL (location-aware `DSLError`).
- **Seven bundled detectors** (run with zero config):
  - `python.injection.os-command` — CWE-78 (high) — OS command injection.
  - `python.injection.sql` — CWE-89 (high) — SQL injection.
  - `python.injection.code-injection` — CWE-94 (critical) — Python code injection
    (`eval`/`exec`/`compile`).
  - `python.traversal.path-traversal` — CWE-22 (high) — path traversal.
  - `python.ssrf.ssrf` — CWE-918 (high) — server-side request forgery.
  - `python.deserialization.unsafe-deserialization` — CWE-502 (critical) —
    unsafe deserialization (`pickle` / unsafe YAML loader).
  - `python.xxe.xxe` — CWE-611 (high) — XML external entity (XXE) injection.
- **DSL parser** (`scanipy.dsl.parse_spec`) — validates every field, all four
  pattern kinds (`call`, `attribute`, `parameter`, `import`), and the flow
  grammar; raises a location-aware `DSLError` on anything outside the DSL.
- **Python frontend & IR** — stdlib-`ast`-based normalized IR with first-class
  import/alias canonicalization and a per-function CFG.
- **Pattern matcher** — segment-wise dotted matching with strict single-`*`
  wildcard placement (exact / trailing-single / leading-greedy).
- **Taint engine** — flow-sensitive forward dataflow, union-at-join, one-sided
  sanitizers (P5), and intra-file interprocedural TITO summaries with witness
  splicing.
- **Verified end-to-end example** ([`docs/examples/end-to-end.md`](docs/examples/end-to-end.md))
  and a **release-readiness checklist** ([`docs/release-readiness.md`](docs/release-readiness.md)).

### Changed

- **Exit-code semantics are now real** (the scan path no longer returns `2` as a
  not-implemented stub): `0` = clean (no finding meets the failure gate), `1` = a
  finding met the gate (`--fail-on`, else the severity threshold), `2` = a
  fatal/usage error (bad path, invalid config, unknown `--detectors` id, unknown
  `rules show` id, or a `rules validate` failure). Per-file parse errors are
  reported on stderr and skipped — they are not fatal.
- **The taint DSL (v0) is locked for this release** — see
  [`docs/dsl-reference.md`](docs/dsl-reference.md). A spec that validates against
  the reference works with 0.2.0 as written.
- **Bumped the `click` floor to `click>=8.2`** (was `click>=8.1`).
- `__version__` is now `0.2.0`.

## [0.1.0] - Unreleased

Initial repository scaffold for **scanipy** (open-source edition) — a local,
private, zero-config taint-tracking SAST CLI for Python. This first release is a
skeleton: it stands up the project structure, CLI, DSL design, and CI so the
engine can be built on top. **The taint scan engine is not implemented yet** —
`scanipy scan` is a stub in this release and does not produce findings.

### Added

- **Runnable CLI skeleton** exposing the planned command surface:
  - `scanipy version` (also `scanipy --version`) — working.
  - `scanipy scan PATH [--format text|json|sarif] [--detectors ID ...] [--severity-threshold low|medium|high|critical] [--fail-on SEV] [--exclude GLOB] [--config FILE] [-o FILE]` — stubbed (not yet implemented).
  - `scanipy rules list | show ID | validate FILE` — stubbed (not yet implemented).
  - Also runnable as `python -m scanipy`.
  - Exit-code convention: `0` = clean (no findings at/above threshold), `1` = findings at/above threshold, `2` = error or not-yet-implemented stub.
- **Simplified taint DSL design (draft / v0)** — declarative YAML detector specs
  with `sources` / `sinks` / `sanitizers` / `propagators`, pattern kinds
  `call`, `attribute`, `parameter`, `import`, and dotted-path patterns with `*`
  wildcards. This is a draft that co-evolves with the engine and is **not** a
  frozen contract. See [`docs/dsl-reference.md`](docs/dsl-reference.md) for the
  canonical schema.
- **Project structure** using a `src` layout (`src/scanipy/`), with the import
  package `scanipy` and the distribution published to PyPI as `scanipy-oss`.
- **Agent team and helper commands** documenting the repo's working model:
  agents `taint-engine`, `detector-author`, `cli-ux`, `qa-test`, `docs-writer`,
  `release-eng`, `code-reviewer`; helper commands `/new-detector`, `/scan-self`,
  `/release`.
- **Packaging** with the `hatchling` build backend, `requires-python >=3.10`,
  runtime dependencies (`click>=8.1`, `rich>=13.7`, `pyyaml>=6.0`), and a dev
  dependency group (`pytest>=8`, `pytest-cov`, `ruff>=0.5`, `mypy>=1.10`,
  `types-PyYAML`, `pre-commit`).
- **CI** with a test matrix across Python 3.10, 3.11, 3.12, and 3.13, plus
  linting/formatting via `ruff` (line length 100, double quotes) and strict type
  checking via `mypy` on `src/`. Configuration lives in `pyproject.toml`.
- **Apache-2.0 license** with an SPDX header (`# SPDX-License-Identifier: Apache-2.0`)
  on every Python source file.

[Unreleased]: https://github.com/scanipy/scanipy-oss/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/scanipy/scanipy-oss/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scanipy/scanipy-oss/releases/tag/v0.1.0
