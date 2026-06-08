---
description: Cut a release — bump the version, update the changelog, run the full gate, verify packaging, and tag.
argument-hint: <version>   e.g. 0.2.0
---

Cut the `$1` release. Act as the **release-eng** agent
(`.claude/agents/release-eng.md`). The PyPI distribution name is `scanipy-oss`.

1. Set `__version__ = "$1"` in `src/scanipy/__init__.py`.
2. Update `CHANGELOG.md`: move `[Unreleased]` items under a new `## [$1]` section
   with today's date; leave a fresh empty `[Unreleased]`.
3. Run the full gate and STOP if anything is red:
   - `ruff check .` · `ruff format --check .` · `mypy src` · `pytest`
4. Verify packaging: `python -m build`, then list the wheel and confirm the
   bundled detector specs (`scanipy/detectors/**/*.yml`) and `py.typed` are inside.
5. Commit (`chore(release): v$1`) on a release branch and open a PR. Only after
   it merges, create and push the tag `v$1` — `release.yml` publishes to PyPI via
   Trusted Publishing on the tag.

Confirm with the user before pushing the tag (publishing is outward-facing and
hard to reverse). Report the gate results and the exact tag you will push.
