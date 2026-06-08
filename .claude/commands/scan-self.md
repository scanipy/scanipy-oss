---
description: Dogfood scanipy on its own source, and run the full local quality gate.
allowed-tools: Bash(*)
---

Run scanipy against itself and verify the project is healthy.

1. Ensure an editable dev install exists (`pip install -e ".[dev]"` if needed).
2. **Dogfood:** run `scanipy scan src` over scanipy's own source and summarize
   the findings. If the scan engine is not implemented yet, say so plainly
   (it currently exits 2) and skip to step 3 — do not pretend it ran.
3. **Quality gate** — run and report each:
   - `ruff check .`
   - `ruff format --check .`
   - `mypy src`
   - `pytest`
4. Summarize: what scanipy found in itself (once the engine exists) and whether
   every gate is green. Flag any finding scanipy reports in its own code as
   something to fix, not to suppress.
