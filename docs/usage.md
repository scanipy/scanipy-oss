# Using scanipy

`scanipy` is a local, private, zero-config taint-tracking SAST CLI for Python. It
follows untrusted data from **sources** to **sinks** (through **sanitizers**) and
reports the **witness trace** — not just a pattern match.

`scan` and `rules` are fully working: `scanipy scan <path>` runs taint analysis
over your Python files with no configuration required, and `scanipy rules`
inspects and validates detector specs. The OSS engine is single-language (Python)
and intra-file — see [Honest scope](#honest-scope).

## Installation

scanipy is **not yet published to PyPI** — install it **from source**. The
installed command is `scanipy`.

```bash
git clone https://github.com/scanipy/scanipy-oss
cd scanipy-oss
pip install -e .          # editable install; or `pip install .`
```

`scanipy-oss` is the **reserved future PyPI distribution name** (the plain name
`scanipy` is squatted by an unrelated package). Publishing under `scanipy-oss` is
planned but **pending** — until then, `pip install scanipy-oss` will not install
this project; use the from-source steps above.

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

`scanipy scan .` walks your Python files, runs the built-in detectors with no
configuration required, and reports any source → sink traces it finds. It exits
`0` when clean, `1` when a finding meets the failure gate (see
[Exit codes](#exit-codes)), and `2` on a fatal/usage error. Files that fail to
parse are reported on stderr and skipped — one bad file never aborts the run, and
`stdout` stays machine-clean for the `json`/`sarif` formats.

Scan a single file or pick formats:

```bash
scanipy scan app.py
scanipy scan src/ --format json -o report.json
scanipy scan . --fail-on high            # CI gate: only fail on high/critical
```

## Command surface

```
scanipy scan PATH [--format text|json|sarif] [--detectors ID ...]
                  [--severity-threshold low|medium|high|critical]
                  [--fail-on SEV] [--exclude GLOB]
                  [--gitignore/--no-gitignore] [--config FILE] [-o FILE]

scanipy rules list | show ID | validate FILE

scanipy version          # also: scanipy --version
```

| Subcommand        | What it does                                              |
| ----------------- | -------------------------------------------------------- |
| `scan`            | Run taint analysis over `PATH` and report findings.       |
| `rules list`      | List the bundled detectors, sorted by id.                 |
| `rules show ID`   | Print one detector spec in full (exit `2` on unknown id). |
| `rules validate FILE` | Validate a spec file against the DSL (exit `2` on a `DSLError`). |
| `version`         | Print the scanipy version.                                |

### Key flags for `scan`

| Flag                          | Purpose                                                                 |
| ----------------------------- | ---------------------------------------------------------------------- |
| `--format text\|json\|sarif`  | Output format. Defaults to human-readable `text`.                      |
| `--detectors ID ...`          | Run only the named detector(s) instead of the full built-in set. An unknown id is a usage error (exit `2`). |
| `--severity-threshold LEVEL`  | Report only findings at or above `low`, `medium`, `high`, or `critical`. |
| `--fail-on SEV`               | Set the severity at or above which scanipy exits non-zero (for CI gating). When unset, the gate is the severity threshold. |
| `--exclude GLOB`              | Skip paths matching a glob, by relative path or basename (repeatable). |
| `--gitignore` / `--no-gitignore` | Honor the scan-root `.gitignore` (default on). Use `--no-gitignore` to scan ignored files too. |
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
| `0`  | Clean — no finding meets the failure gate.                   |
| `1`  | A finding met the gate (`--fail-on`, else the severity threshold). |
| `2`  | A fatal or usage error: bad path, invalid config, unknown `--detectors` id, unknown `rules show` id, or a `rules validate` failure. |

Per-file parse errors are **not** fatal: they are reported on stderr and the run
continues over the remaining files.

## Continuous integration

The snippet below shows how a GitHub Actions workflow will run scanipy and upload a
SARIF report to **GitHub code scanning**. A few details matter:

- Grant `security-events: write` so the upload step is allowed to post results.
- Use `if: always()` on the upload step. With `--fail-on`, the scanipy step exits
  `1` when there are findings, which would otherwise skip the upload. `if:
  always()` makes sure the SARIF is uploaded even when scanipy fails the job.

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
        # Not on PyPI yet — install from source (pin a tag/SHA in real pipelines).
        run: pip install "git+https://github.com/scanipy/scanipy-oss"

      - name: Run scanipy
        run: scanipy scan . --format sarif -o scanipy.sarif --fail-on high

      - name: Upload SARIF to GitHub code scanning
        if: always()            # upload even if scanipy exited 1 (findings)
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scanipy.sarif
```

## Inspecting detectors

```bash
scanipy rules list                              # all bundled detectors, sorted by id
scanipy rules show python.injection.os-command  # one spec in full
scanipy rules validate my-detector.yml          # check a spec against the DSL
```

`rules show` exits `2` and lists the available ids if the id is unknown;
`rules validate` exits `2` and prints the `DSLError` line if the spec is invalid.

## Optional config file

scanipy is **zero-config** by design: the built-in detectors run with no setup. A
config file is entirely optional — reach for it when you want to pin defaults
(formats, thresholds, excludes, detector selection) instead of repeating flags.
Command-line flags always win over the config file, which always wins over the
built-in defaults.

scanipy looks for a `.scanipy.yml` next to the scan path (or a `[tool.scanipy]`
table in a `pyproject.toml` there); discovery is shallow and does not walk parent
directories. Pass `--config FILE` to point at one explicitly.

```yaml
# .scanipy.yml — every key is optional
severity_threshold: medium          # low | medium | high | critical
fail_on: high                       # gate for a non-zero exit
output_format: text                 # text | json | sarif
detectors:                          # limit to specific detector ids
  - python.injection.os-command
exclude:                            # globs to skip
  - "tests/*"
gitignore: true                     # honor the scan-root .gitignore
```

An unknown key or a bad enum is a hard error (exit `2`) — a typo never silently
changes the scan. The `[tool.scanipy]` table in `pyproject.toml` requires Python
3.11+ (it relies on the stdlib `tomllib`); on 3.10 use `.scanipy.yml`.

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
