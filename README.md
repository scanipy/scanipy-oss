<h1 align="center">scanipy</h1>

<p align="center">
  <strong>Local, private, taint-tracking SAST for your code.</strong><br>
  The open-source edition of <a href="https://scanipy.com">scanipy</a>.
</p>

<p align="center">
  <a href="https://github.com/scanipy/scanipy-oss/actions"><img alt="CI" src="https://img.shields.io/badge/CI-pending-lightgrey"></a>
  <img alt="PyPI" src="https://img.shields.io/badge/PyPI-not%20yet%20published-lightgrey">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-green"></a>
  <img alt="Status" src="https://img.shields.io/badge/status-alpha-orange">
</p>

---

> **0.2.0 — the engine works.** `scanipy scan` now performs real taint analysis:
> it follows untrusted data from sources to sinks and reports the
> `source → … → sink` witness behind every finding. Seven detectors ship today
> (see [the catalog](#detector-catalog)). **Install is from source for now** —
> scanipy is not yet on PyPI (see [Install](#install)).

## Why scanipy

Most free scanners pattern-match: they flag any `os.system(...)` they see,
whether or not attacker-controlled data can reach it. That means noise.

scanipy does **taint tracking** instead. It follows untrusted data from a
**source** (like `input()` or a web request) through your code to a dangerous
**sink** (like an OS command or a SQL query), and reports the **data-flow trace**
behind every finding — so you see *why* something is exploitable, not just where
a risky function appears. Sanitizers on the path suppress the finding.

- 🔒 **Local & private** — your code never leaves your machine.
- 🧭 **Witness-backed** — every finding shows the `source → … → sink` path.
- 🧩 **Declarative detectors** — coverage is YAML, not engine hacking.
- ⚡ **Zero-config** — built-in detectors run with no setup.

## Install

scanipy is **not yet published to PyPI** — install it **from source**:

```bash
git clone https://github.com/scanipy/scanipy-oss
cd scanipy-oss
pip install -e .          # or: pip install .
```

The installed command is `scanipy` (you can also run `python -m scanipy`).

> **Heads up.** `scanipy-oss` is the **reserved future PyPI distribution name**;
> publishing it is planned but **pending** (no release is on PyPI yet). Until then
> `pip install scanipy-oss` will **not** install this project — use the
> from-source steps above. Requires Python 3.10+.

## Quickstart

```bash
scanipy scan .            # scan the current project
scanipy scan app.py       # scan a single file
scanipy rules list        # list the bundled detectors
scanipy version           # print the version
scanipy --help            # full command reference
```

Useful flags (on the `scan` command):

| Flag | Purpose |
|---|---|
| `--format text\|json\|sarif` | Output format (SARIF uploads straight to GitHub code scanning). |
| `--severity-threshold` | Hide findings below a severity. |
| `--fail-on` | Control the non-zero exit threshold for CI. |
| `--detectors ID` | Run only specific detectors. |
| `--exclude GLOB` | Skip paths. |

**Exit codes:** `0` clean · `1` findings at/above threshold · `2` error.

## How detectors work

Detectors are declarative taint-DSL specs — `sources`, `sinks`, `sanitizers`,
and `propagators`:

```yaml
id: python.injection.os-command
name: OS command injection
cwe: CWE-78
severity: high
languages: [python]
sources:
  - { kind: call, pattern: "input" }
sanitizers:
  - { kind: call, pattern: "shlex.quote" }
sinks:
  - { kind: call, pattern: "os.system", args: [0] }
```

Full schema: [docs/dsl-reference.md](docs/dsl-reference.md). Adding coverage:
[docs/writing-detectors.md](docs/writing-detectors.md).

## Detector catalog

Seven detectors ship in 0.2.0 and run with zero config (`scanipy rules list`):

| Detector id | CWE | Severity | Finds |
|---|---|---|---|
| `python.injection.os-command` | CWE-78 | high | OS command injection |
| `python.injection.sql` | CWE-89 | high | SQL injection |
| `python.injection.code-injection` | CWE-94 | critical | Python code injection (`eval`/`exec`/`compile`) |
| `python.traversal.path-traversal` | CWE-22 | high | Path traversal |
| `python.ssrf.ssrf` | CWE-918 | high | Server-side request forgery |
| `python.deserialization.unsafe-deserialization` | CWE-502 | critical | Unsafe deserialization (`pickle`/unsafe YAML) |
| `python.xxe.xxe` | CWE-611 | high | XML external entity (XXE) injection |

See a real scan end-to-end — the exact witness output and exit codes — in
[docs/examples/end-to-end.md](docs/examples/end-to-end.md).

## Documentation

- [Usage](docs/usage.md)
- [End-to-end example](docs/examples/end-to-end.md)
- [Writing detectors](docs/writing-detectors.md)
- [Taint-DSL reference](docs/dsl-reference.md)
- [Contributing](CONTRIBUTING.md)

## scanipy Cloud

scanipy OSS is a single-language, local CLI. For teams that need more,
[**scanipy Cloud**](https://scanipy.com) adds
multi-language interprocedural taint analysis, pull-request and CI integration,
finding deduplication and baselines across many repositories, and a multi-tenant
dashboard with auditable provenance. The OSS CLI is the free taste; the platform
is the full meal.

## Status & roadmap

0.2.0 makes the tool work end-to-end: the Python frontend, the DSL parser, the
taint engine (intra-file, including intra-file interprocedural via function
summaries), and the seven detectors above. **Honest scope (P7):** the OSS engine
is single-language (Python) and does not do cross-file / whole-program analysis —
that lives in [scanipy Cloud](#scanipy-cloud). scanipy is **not yet on PyPI**;
publishing is the next milestone. See [CHANGELOG.md](CHANGELOG.md).

## Contributing

Contributions are very welcome — especially new detectors. See
[CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

[Apache-2.0](LICENSE) © The scanipy contributors.
