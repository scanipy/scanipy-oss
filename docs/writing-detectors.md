# Writing detectors

Detectors are how scanipy knows what to look for. They are **declarative YAML
specs** written in scanipy's simplified taint DSL — not Python, not regexes.
A detector describes *where untrusted data comes from*, *what neutralizes it*,
and *where it must never arrive unneutralized*. The engine does the actual
tracking; your spec just declares the rules.

> **Draft notice.** The taint DSL is **draft / v0**. It co-evolves with the
> engine and is **not** a frozen contract — field names and behavior can change
> between releases. Pin a detector-pack version if you need stability.

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

## Validating a spec

Once you've written or edited a spec, check that it's well-formed:

```
scanipy rules validate src/scanipy/detectors/<class>/<name>.yml
```

This checks the YAML against the DSL. You can also list and inspect detectors:

```
scanipy rules list
scanipy rules show <id>
```

> Heads up: this is an early scaffold. Several subcommands are still stubs while
> the engine and DSL settle, so expect rough edges and behavior to change as the
> draft DSL evolves.

## Principles to keep in mind

- **Declarative** — detection logic belongs in the DSL spec, not in engine code.
- **Witness-backed** — every finding carries its source-to-sink trace.
- **Deterministic** — the same code plus the same detector-pack version produces
  identical findings.
- **Honest scope** — the OSS engine is single-language and intraprocedural-
  leaning. Write detectors that fit that reality rather than assuming
  cross-function or cross-file tracking.
