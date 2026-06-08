<h1 align="center">scanipy</h1>

<p align="center">
  <strong>Local, private, taint-tracking SAST for your code.</strong><br>
  The open-source edition of <a href="https://scanipy.dev">scanipy</a>.
</p>

<p align="center">
  <a href="https://github.com/scanipy/scanipy-oss/actions"><img alt="CI" src="https://img.shields.io/badge/CI-pending-lightgrey"></a>
  <a href="https://pypi.org/project/scanipy-oss/"><img alt="PyPI" src="https://img.shields.io/badge/PyPI-scanipy--oss-blue"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-green"></a>
  <img alt="Status" src="https://img.shields.io/badge/status-alpha-orange">
</p>

---

> **🚧 Early development.** This repository is the **0.1.0 scaffold**: a runnable
> CLI skeleton, the project architecture, and the taint-DSL design. The scan
> engine is not implemented yet — `scanipy scan` is currently a stub. Star and
> watch the repo to follow along.

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

```bash
pip install scanipy-oss
```

The installed command is `scanipy` (you can also run `python -m scanipy`).

## Quickstart

```bash
scanipy scan .            # scan the current project   (coming soon)
scanipy scan app.py       # scan a single file         (coming soon)
scanipy version           # works today
scanipy --help            # works today
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

## Documentation

- [Usage](docs/usage.md)
- [Writing detectors](docs/writing-detectors.md)
- [Taint-DSL reference](docs/dsl-reference.md)
- [Contributing](CONTRIBUTING.md)

## scanipy Cloud

scanipy OSS is a single-language, local CLI. For teams that need more,
[**scanipy Cloud**](https://scanipy.dev) *(link is a placeholder)* adds
multi-language interprocedural taint analysis, pull-request and CI integration,
finding deduplication and baselines across many repositories, and a multi-tenant
dashboard with auditable provenance. The OSS CLI is the free taste; the platform
is the full meal.

## Status & roadmap

0.1.0 ships the scaffold (CLI skeleton, architecture, DSL design). Next up: the
Python frontend and taint engine, the DSL parser, and the first working
detectors. See [CHANGELOG.md](CHANGELOG.md).

## Contributing

Contributions are very welcome — especially new detectors. See
[CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

[Apache-2.0](LICENSE) © The scanipy contributors.
