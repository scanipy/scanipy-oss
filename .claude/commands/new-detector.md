---
description: Scaffold a new detector — spec, true-positive + true-negative fixtures, and a registration test.
argument-hint: <class> <name> <CWE-id>   e.g. injection sql CWE-89
---

Scaffold a new scanipy detector. Arguments: class=`$1`, name=`$2`, cwe=`$3`.

Act as the **detector-author** agent (`.claude/agents/detector-author.md`).
Read `docs/dsl-reference.md` (the canonical schema) and
`.claude/rules/detector-quality.md` first, then:

1. Create `src/scanipy/detectors/$1/$2.yml` with id `python.$1.$2`, the given
   CWE `$3`, a clear `severity`, a `message` that states the flaw **and** the
   fix, and `sources` / `sinks` / `sanitizers` / `propagators` drawn only from
   the DSL in `docs/dsl-reference.md`.
2. Create the **true-positive** fixture
   `tests/fixtures/python/vulnerable/$2.py` — minimal code the detector MUST flag.
3. Create the **true-negative** fixture
   `tests/fixtures/python/safe/$2.py` — the sanitized/safe counterpart it MUST NOT flag.
4. Add/extend a test asserting the spec validates, the TP is flagged, and the TN
   is clean (principle P5). If the engine isn't implemented yet, at minimum test
   that the spec parses/validates.
5. Run `scanipy rules validate src/scanipy/detectors/$1/$2.yml` (once available),
   then `ruff check .`, `mypy src`, and `pytest`.

Do not add detector-specific logic to engine or CLI code — keep it declarative (P4).
Report what you created and the test results.
