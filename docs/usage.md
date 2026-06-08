# Using scanipy

`scanipy` is a local, private, zero-config taint-tracking SAST CLI for Python. It
follows untrusted data from **sources** to **sinks** (through **sanitizers**) and
reports the **witness trace** — not just a pattern match.

> **Early scaffold — read this first.** This is the `0.1.0` open-source edition.
> The CLI surface below is the *intended* interface and it is wired up, but the
> `scan` and `rules` subcommands are **not-yet-implemented stubs**: they currently
> exit with code `2` (not-yet-implemented). The taint engine is coming soon. The
> examples here show how the tool *will* be used so your scripts and CI can be
> ready — they will not produce findings yet. We would rather under-promise than
> overstate what works.

## Installation

scanipy is distributed on PyPI as **`scanipy-oss`** (the plain name `scanipy` is
squatted by an unrelated package). The installed command is `scanipy`.

```bash
pip install scanipy-oss
```

Verify the install:

```bash
scanipy version
# or
scanipy --version
```

You can also run it as a module, which is handy in environments where the console
script isn't on your `PATH`:

```bash
python -m scanipy version
```

Requires Python 3.10 or newer (tested on 3.10, 3.11, 3.12, and 3.13).

## Quickstart

Scan the current directory:

```bash
scanipy scan .
```

> In `0.1.0` this prints a not-yet-implemented notice and exits `2`. Once the
> engine lands, `scanipy scan .` will walk your Python files, run the built-in
> detectors with no configuration required, and report any source → sink traces it
> finds.

## Command surface

```
scanipy scan PATH [--format text|json|sarif] [--detectors ID ...]
                  [--severity-threshold low|medium|high|critical]
                  [--fail-on SEV] [--exclude GLOB] [--config FILE] [-o FILE]

scanipy rules list | show ID | validate FILE

scanipy version          # also: scanipy --version
```

| Subcommand        | Status in 0.1.0           | What it will do                                  |
| ----------------- | ------------------------- | ------------------------------------------------ |
| `scan`            | **stub (coming soon)**    | Run taint analysis over `PATH` and report findings. |
| `rules`           | **stub (coming soon)**    | List, show, and validate detector specs.         |
| `version`         | works                     | Print the scanipy version.                       |

### Key flags for `scan`

| Flag                          | Purpose                                                                 |
| ----------------------------- | ---------------------------------------------------------------------- |
| `--format text\|json\|sarif`  | Output format. Defaults to human-readable `text`.                      |
| `--detectors ID ...`          | Run only the named detector(s) instead of the full built-in set.        |
| `--severity-threshold LEVEL`  | Report only findings at or above `low`, `medium`, `high`, or `critical`. |
| `--fail-on SEV`               | Set the severity at or above which scanipy exits non-zero (for CI gating). |
| `--exclude GLOB`              | Skip paths matching a glob (repeatable).                                |
| `--config FILE`               | Load settings from a config file (see below).                          |
| `-o FILE`                     | Write output to a file instead of stdout.                              |

## Output formats

`scan` supports three output formats via `--format`:

- **`text`** (default) — a readable, colorized report intended for terminals.
- **`json`** — machine-readable findings for your own tooling and pipelines.
- **`sarif`** — [SARIF](https://sarifweb.azurewebsites.net/) for integration with
  code-scanning platforms such as GitHub code scanning (see the CI snippet below).

Every finding is **witness-backed**: it carries the source → sink trace that
justifies it, in whichever format you choose.

## Exit codes

scanipy uses exit codes so it can gate CI:

| Code | Meaning                                                      |
| ---- | ----------------------------------------------------------- |
| `0`  | Clean — no findings at or above the configured threshold.    |
| `1`  | Findings at or above the threshold (and/or `--fail-on`).     |
| `2`  | Error, or a not-yet-implemented stub (which is what `scan` and `rules` return today in `0.1.0`). |

## Continuous integration

The snippet below shows how a GitHub Actions workflow will run scanipy and upload a
SARIF report to **GitHub code scanning**. A few details matter:

- Grant `security-events: write` so the upload step is allowed to post results.
- Use `if: always()` on the upload step. With `--fail-on`, the scanipy step exits
  `1` when there are findings — and today the `scan` stub exits `2` — both of which
  would otherwise skip the upload. `if: always()` makes sure the SARIF is uploaded
  even when scanipy fails the job.

> Heads-up: because `scan` is a stub in `0.1.0`, this workflow currently exits `2`
> and uploads an empty/placeholder report. Add it now so it's ready, or wait until
> the engine ships — your call.

```yaml
name: scanipy
on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # required to upload SARIF
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install scanipy
        run: pip install scanipy-oss

      - name: Run scanipy
        run: scanipy scan . --format sarif -o scanipy.sarif --fail-on high

      - name: Upload SARIF to GitHub code scanning
        if: always()            # upload even if scanipy exited 1 (findings) or 2 (stub)
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scanipy.sarif
```

## Optional config file

scanipy is **zero-config** by design: the built-in detectors run with no setup. A
config file is entirely optional — reach for it when you want to pin defaults
(formats, thresholds, excludes, detector selection) instead of repeating flags.

```bash
scanipy scan . --config .scanipy.yml
```

The config schema co-evolves with the engine and will be documented as `scan`
matures.

## Honest scope

The OSS tool is single-language (Python) and intraprocedural-leaning taint
analysis. It does **not** claim the interprocedural, multi-tenant, or attested
guarantees of any hosted platform. What it does promise: scanning stays **local
and private** — your code is never sent over the network — and findings are
**deterministic** (same code + same detector-pack version ⇒ identical findings).

## Learn more

- **[DSL reference](dsl-reference.md)** — the detector spec schema (sources,
  sinks, sanitizers, propagators; pattern kinds and dotted-path patterns).
- **[Writing detectors](writing-detectors.md)** — author your own detectors in the
  taint DSL.
- Project home: <https://github.com/scanipy/scanipy-oss>
