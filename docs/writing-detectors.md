# Writing detectors

Detectors are how scanipy knows what to look for. They are **declarative YAML
specs** written in scanipy's simplified taint DSL — not Python, not regexes.
A detector describes *where untrusted data comes from*, *what neutralizes it*,
and *where it must never arrive unneutralized*. The engine does the actual
tracking; your spec just declares the rules.

> **Schema status.** The taint DSL is **v0, locked for 0.2.0** — the schema in
> [the DSL reference](dsl-reference.md) is the contract the 0.2.0 engine
> implements and will not change within the release. (Pre-1.0.0 it may still
> evolve in a future minor; pin a detector-pack version if you need
> cross-version stability.)

## Where detectors live

Built-in detectors live under the package, grouped by vulnerability class:

```
src/scanipy/detectors/<class>/<name>.yml
```

For example, the bundled OS-command-injection detector lives at
`src/scanipy/detectors/injection/os-command.yml`. The `<class>` folder is the
broad category (e.g. `injection`, `path-traversal`, `secrets`) and `<name>` is
the specific rule (e.g. `os-command`, `sql`). The detector's `id` mirrors this
path as `<language>.<class>.<name>` — here, `python.injection.os-command`. Use
the `.yml` extension.

These ship with scanipy and run with zero config — no setup required to use the
built-ins.

## The mental model: source → sanitizer → sink

scanipy is a taint tracker. Instead of matching a single suspicious pattern, it
**follows untrusted data** through your program. Three ideas do all the work:

- **Source** — where untrusted (tainted) data enters. A web request parameter,
  a CLI argument, a file you read, an environment variable.
- **Sink** — a dangerous operation that must not receive tainted data. Running a
  shell command, building a SQL query, opening a file path.
- **Sanitizer** — something that makes tainted data safe again (escaping,
  quoting, validating, allow-listing). Data that passes through a sanitizer is
  no longer considered tainted on its way to a sink.

A finding is reported when tainted data flows from a **source** to a **sink**
**without** passing through a **sanitizer**. Every finding carries the witness
trace — the actual source-to-sink path — so you can see *why* it fired, not just
*that* it fired.

(There is a fourth piece, **propagators**, for describing how taint moves
through helper calls. See the schema reference for details.)

### A small illustrative example

This is a *sketch* to convey the shape of a spec, not the full schema. It uses
the DSL vocabulary — `sources`, `sinks`, `sanitizers` — with pattern `kind`s
(`call`, `attribute`, `parameter`, `import`) and dotted paths where `*` is a
wildcard.

```yaml
id: python.injection.os-command
sources:
  - kind: attribute        # untrusted web-request data
    pattern: flask.request.*
sinks:
  - kind: call             # the dangerous operation
    pattern: os.system
sanitizers:
  - kind: call             # neutralizes the data before it reaches the sink
    pattern: shlex.quote
```

In plain English: *if a value read from `flask.request.args` reaches
`os.system` without first going through `shlex.quote`, report it.*

For the authoritative, field-by-field schema — every key, every `kind`, the
pattern grammar, propagators, severity, metadata — see
[the DSL reference](dsl-reference.md). Do not treat the snippet above as
complete.

## Every detector ships two fixtures (mandatory)

This is **principle P5**, and it is not optional. Each detector must ship:

1. A **true-positive** fixture — a small piece of code where the vulnerable flow
   exists and the detector **must** fire.
2. A **true-negative** fixture — typically the *same* code with a sanitizer
   correctly applied (or the source removed), where the detector **must not**
   fire.

The pair is what proves a detector both *catches* the bug and *doesn't cry
wolf* once the bug is fixed. A detector without both fixtures is incomplete.

### Fixture-pairing convention

Fixtures live in two sibling trees and pair **by filename**:

```
tests/fixtures/python/vulnerable/<name>.py   # must be flagged   (true positive)
tests/fixtures/python/safe/<name>.py         # must stay clean   (true negative)
```

Use the **same `<name>.py`** in both trees so the pair is discoverable
automatically — `<name>` typically matches the detector's `<name>` (e.g.
`os-command.py`, `sql.py`). Interprocedural cases that exercise function
summaries are prefixed `interproc-` (e.g. `interproc-os-command.py`). Fixtures
are intentionally vulnerable sample programs: they are analysis **DATA**, excluded
from `ruff`/`mypy` — never "fix" a fixture.

### Sanitizer soundness is one-sided

Be deliberately conservative about what you declare a sanitizer. The two failure
modes are not symmetric:

- If scanipy **fails to recognize** a real sanitizer, it over-reports: you get a
  **false positive**. Noisy, but safe — a human can dismiss it.
- If you **wrongly declare** something a sanitizer when it doesn't actually make
  the data safe, scanipy will **silently suppress a real vulnerability**. That
  is the dangerous direction.

So the rule of thumb: **prefer a false positive over a missed bug.** Only list a
sanitizer when you are confident it truly neutralizes the taint for that sink.
When in doubt, leave it out.

## Scaffolding a new detector: `/new-detector`

The fastest way to start is the `/new-detector` helper. It scaffolds the spec
file in the right place under `src/scanipy/detectors/<class>/` and the matching
true-positive / true-negative fixtures, so you begin with a working skeleton
that already satisfies P5. Fill in the sources, sinks, and sanitizers from
there.

## Anatomy of a real detector

The bundled OS-command detector,
[`src/scanipy/detectors/injection/os-command.yml`](../src/scanipy/detectors/injection/os-command.yml),
is a complete, shipping spec. Every field below is real:

```yaml
id: python.injection.os-command      # <language>.<class>.<name>
name: OS command injection
cwe: CWE-78
severity: high
languages: [python]
message: >                           # shown on every finding: flaw + fix
  Untrusted input reaches an OS command without sanitization, allowing an
  attacker to execute arbitrary commands. Prefer a list argv with shell=False,
  or quote inputs with shlex.quote.
metadata:
  owasp: "A03:2021-Injection"
  references:
    - https://cwe.mitre.org/data/definitions/78.html

sources:                             # where untrusted data enters
  - { kind: call, pattern: "input" }
  - { kind: attribute, pattern: "flask.request.*" }

sanitizers:                          # what neutralizes it (one-sided trust, P5)
  - { kind: call, pattern: "shlex.quote" }

sinks:                               # where tainted data becomes dangerous
  - { kind: call, pattern: "os.system", args: [0] }
  - { kind: call, pattern: "os.popen", args: [0] }
  - { kind: call, pattern: "subprocess.*", when: { keyword: { shell: true } } }

propagators:                         # how taint moves through helper calls
  - { kind: call, pattern: "str.format", flow: { from: any-arg, to: return } }
  - { kind: call, pattern: "os.path.join", flow: { from: any-arg, to: return } }
```

Reading it as taint flow:

- **Sources** seed taint at `input(...)` and any `flask.request.*` attribute.
- **Sinks** fire only where it matters: `os.system`/`os.popen` are flagged only on
  argument `0` (`args: [0]`); a `subprocess.*` call is flagged only when it is
  invoked with `shell=True` (`when: { keyword: { shell: true } }`) — a list-argv
  `subprocess.run([...])` is safe and is not matched.
- **Sanitizer** `shlex.quote` clears taint, so a quoted value reaching a sink is
  not a finding.
- **Propagators** carry taint through `str.format` and `os.path.join` so a sink
  fed by `"...".format(tainted)` is still caught.

For the authoritative meaning of every key (`args`, `when`, the wildcard rules,
the flow vocabulary), see [the DSL reference](dsl-reference.md).

## Validating a spec

Once you've written or edited a spec, check that it's well-formed — `rules`
commands are fully working:

```
scanipy rules validate src/scanipy/detectors/<class>/<name>.yml
```

`rules validate` checks the YAML against the DSL: it prints
`<file>: valid (<id>)` on success, and on a malformed spec it prints the
location-aware `DSLError` line (`path:line:col: [id] field: message`) and exits
`2`. You can also list and inspect the bundled detectors:

```
scanipy rules list                  # all detectors, sorted by id, with CWE + severity
scanipy rules show <id>             # one spec in full (exit 2 on an unknown id)
```

## Principles to keep in mind

- **Declarative** — detection logic belongs in the DSL spec, not in engine code.
- **Witness-backed** — every finding carries its source-to-sink trace.
- **Deterministic** — the same code plus the same detector-pack version produces
  identical findings.
- **Honest scope** — the OSS engine is single-language and intraprocedural-
  leaning. Write detectors that fit that reality rather than assuming
  cross-function or cross-file tracking.
