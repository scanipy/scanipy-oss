# Release readiness — 0.2.0

The human checklist for cutting **0.2.0**. Work top to bottom; every box must be
checked before the final step. The final step is a deliberate **STOP** — v1 does
**not** publish to PyPI or push a tag.

> **Divergence from `/release` for v1.** The `.claude/commands/release.md` helper
> (the `release-eng` workflow) ends by creating and pushing the `v$1` tag, which
> triggers `release.yml` to publish to PyPI via Trusted Publishing. **For 0.2.0
> that last part does not run.** v1's Definition of Done is explicitly *no PyPI
> publish* (see [PLAN.md](../PLAN.md) §1 and §8): scanipy is installed from source
> and `scanipy-oss` stays a reserved-but-unpublished distribution name. Follow
> this checklist instead of the helper's publish/tag steps — do steps 1–2 of
> `/release` (version + changelog), run its gate, and then **STOP here** rather
> than tagging.

## 1. Version & changelog

- [ ] `src/scanipy/__init__.py` has `__version__ = "0.2.0"`, and **no other**
      version literal exists anywhere in the source (`pyproject.toml` sources the
      version from `__init__.py` via Hatchling).
- [ ] `scanipy version` prints `scanipy 0.2.0` and `scanipy --version` agrees.
- [ ] `CHANGELOG.md` has a dated `## [0.2.0] - 2026-06-09` section that lists every
      shipped detector (id + CWE), the exit-code semantics (`0`/`1`/`2`), and the
      `click>=8.2` floor; there is a fresh empty `## [Unreleased]`; the link refs
      at the bottom resolve.

## 2. Docs honesty (P7)

- [ ] README and `docs/usage.md` describe `scan` / `rules` as **working** — no
      "coming soon" / "stub" / "scaffold" language remains.
- [ ] Install instructions are **from source** (`pip install -e .` / clone). The
      docs state plainly that PyPI publishing is **pending** and that
      `pip install scanipy-oss` does **not** install this project yet.
- [ ] `docs/dsl-reference.md` marks the v0 schema **locked for 0.2.0**, documents
      `DSLError` and the enforced validation rules (including the strict
      single-`*` wildcard-placement rule), and keeps the v1 known-limitations.
- [ ] `docs/writing-detectors.md` has no "subcommands are stubs" notice, documents
      `rules validate` / `list` / `show`, the fixture-pairing convention
      (`tests/fixtures/python/{vulnerable,safe}/<name>.py`), and an os-command
      anatomy walkthrough that matches the real spec.
- [ ] `docs/examples/end-to-end.md` matches the real CLI output byte-for-byte
      (the `tests/docs/` suite enforces this).

## 3. Gate (must be green on 3.10–3.13)

- [ ] `ruff check .`
- [ ] `ruff format --check .`
- [ ] `mypy src`
- [ ] `pytest --cov=scanipy --cov-fail-under=90`
- [ ] CI is green on the full Python matrix (3.10, 3.11, 3.12, 3.13).

## 4. Behavior demonstrated

- [ ] `scanipy scan` flags every vulnerable fixture and clears every safe
      counterpart (the P5 TP/TN matrix passes).
- [ ] Output is deterministic — scanning the same corpus twice is byte-identical
      for `text` / `json` / `sarif` (P3).
- [ ] A scan performs no network I/O (P1).

## 5. Packaging sanity (build only — do NOT upload)

- [ ] `python -m build` succeeds.
- [ ] The built wheel contains the bundled detector specs
      (`scanipy/detectors/**/*.yml`) and `py.typed`.
- [ ] **Do not** run `twine upload` and **do not** push a tag.

## 6. STOP — no publish in v1

> 🛑 **STOP HERE.** 0.2.0 ships **from source only**. Do **not** create or push the
> `v0.2.0` tag, do **not** publish to PyPI, and do **not** trigger `release.yml`.
> Publishing is a separate, future, outward-facing decision (and the
> `scanipy-oss` PyPI name is still merely reserved). When the project is ready to
> publish, that will be its own release-readiness pass — this checklist ends here.
