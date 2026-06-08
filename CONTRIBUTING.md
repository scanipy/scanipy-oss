# Contributing to scanipy

Thanks for your interest in **scanipy** — the local, private, zero-config taint-tracking SAST CLI for Python. scanipy follows untrusted data from sources to sinks (through sanitizers) and reports the witness trace, not just pattern matches. This is an early scaffold, so a lot is still stubbed out and the taint DSL is a draft that co-evolves with the engine. Contributions of all sizes are welcome: bug reports, new detectors, docs, tests, and engine work. Please keep changes lean, honest about what works, and aligned with the project principles (local & private, witness-backed findings, determinism, declarative detectors).

## Dev setup

scanipy uses a `src/` layout and the [hatchling](https://hatch.pypa.io/) build backend. Requires Python >= 3.10.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

The editable install (`-e ".[dev]"`) pulls in the runtime and dev dependencies and puts the `scanipy` command on your `PATH` (you can also run it as `python -m scanipy`). `pre-commit install` wires up the lint/format/type hooks so they run automatically on commit.

## Running checks

Run these locally before opening a pull request — CI runs the same checks across Python 3.10, 3.11, 3.12, and 3.13:

```bash
ruff check .       # lint
ruff format .      # format
mypy src           # type-check (strict on src/)
pytest             # tests
```

## Branch protection & the PR workflow

`main` is a protected trunk: **all changes land via pull request — never push to `main` directly.** Work on a feature branch, open a PR, and merge it once CI is green.

Three layers enforce this:

1. **Server-side (authoritative):** a GitHub branch ruleset on `main` requires a pull request and blocks direct pushes, branch deletion, and force-pushes. This is the real lock.
2. **CI backstop:** `.github/workflows/enforce-pr-only-merges.yml` fails red if a commit reaches `main` outside the GitHub merge UI.
3. **Local (run once):** `pre-commit install` arms both a commit guard (`no-commit-to-branch`) and a push guard (`no-push-to-main`), so your clone refuses commits and pushes that target `main`. Emergency bypass (avoid): `git commit/push --no-verify`.

Maintainers can (re)apply the server-side ruleset with:

```bash
gh api -X POST repos/scanipy/scanipy-oss/rulesets --input - <<'JSON'
{
  "name": "protect-main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
  "rules": [
    { "type": "pull_request" },
    { "type": "deletion" },
    { "type": "non_fast_forward" }
  ]
}
JSON
```

## Adding a detector

Detectors are declarative YAML specs — detection logic lives in the DSL, not in engine code (principle P4). To add one:

- Read the guide: [docs/writing-detectors.md](docs/writing-detectors.md). For the canonical DSL schema, see [docs/dsl-reference.md](docs/dsl-reference.md).
- Scaffold it with the `/new-detector` helper command.
- **Ship both fixtures.** Every detector MUST come with a true-positive fixture (code that should be flagged) AND a true-negative fixture (code that should not be flagged) — this is principle **P5**, and it is required. Sanitizer soundness is one-sided: a missed sanitizer is a false positive, never a silently-suppressed real vulnerability. When in doubt, prefer reporting over suppressing.

## Coding conventions

- **Formatting & lint:** [ruff](https://docs.astral.sh/ruff/), configured in `pyproject.toml` — line length **100**, **double quotes**. Run `ruff format .` and `ruff check .`.
- **SPDX header:** every Python source file starts with:

  ```python
  # SPDX-License-Identifier: Apache-2.0
  ```

- **Type hints:** full type hints on all code; `mypy` runs in **strict** mode on `src/`. Keep `mypy src` clean.
- **Commit messages:** use [Conventional Commits](https://www.conventionalcommits.org/) — e.g. `feat(detectors): add subprocess shell-injection detector`, `fix(cli): correct exit code for empty scan`, `docs: clarify DSL parameter pattern`.

## Licensing

By contributing, you agree that your contributions are licensed under the project's [Apache-2.0](LICENSE) license.

## Code of Conduct

Participation in this project is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## The agent-team working model

scanipy is developed with a small team of role-scoped agents, each owning a slice of the codebase. Their definitions live under `.claude/`.

- **taint-engine** — the source→sink taint analysis core.
- **detector-author** — authors and maintains the declarative YAML detectors.
- **cli-ux** — the `scanipy` command-line surface and output formats.
- **qa-test** — fixtures, test coverage, and the true-positive / true-negative discipline.
- **docs-writer** — user and contributor documentation.
- **release-eng** — packaging, versioning, and releases.
- **code-reviewer** — review for correctness, soundness, and adherence to the principles above.

Helper commands `/new-detector`, `/scan-self`, and `/release` support these roles. You don't need to use the agents to contribute — they're how the maintainers organize the work, and the definitions in `.claude/` are a useful map of who owns what.
