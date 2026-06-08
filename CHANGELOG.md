# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0.0, anything MAY change between releases. Public
interfaces (the CLI surface and the taint DSL) are still settling, and breaking
changes can land in any minor release until 1.0.0.

## [Unreleased]

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

[Unreleased]: https://github.com/scanipy/scanipy-oss/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/scanipy/scanipy-oss/releases/tag/v0.1.0
