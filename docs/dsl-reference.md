# scanipy taint-DSL reference

> **Status: draft / v0.** The engine that consumes these specs is still being
> built, so this schema **co-evolves with the engine** — fields may change
> before the first engine release. This file is the *single source of truth* for
> the spec format; other docs link here rather than restating it.
>
> The **parser is implemented** (`scanipy.dsl.parse_spec`): it validates every
> field, all four pattern kinds (`call`, `attribute`, `parameter`, `import`), and
> the flow grammar, raising a location-aware `DSLError` on anything outside the
> DSL. See [Validation & errors](#validation--errors).

A **detector** is a declarative YAML file that tells scanipy how to find one
class of vulnerability by *taint tracking*: follow untrusted data from a
**source**, through optional **propagators**, to a dangerous **sink** — unless a
**sanitizer** neutralizes it on the way. Detection logic lives entirely in these
specs; the engine is class-agnostic (principle **P4**).

Bundled specs live in `src/scanipy/detectors/<class>/<name>.yml` and ship as
package data.

---

## File layout

```yaml
id: python.injection.os-command      # unique id: <language>.<class>.<name>
name: OS command injection           # short human title
cwe: CWE-78                          # primary CWE
severity: high                       # low | medium | high | critical
languages: [python]                  # languages this spec applies to
message: >                           # shown on every finding; say what + how to fix
  Untrusted input reaches an OS command without sanitization...
metadata:                            # optional, free-form
  owasp: "A03:2021-Injection"
  references:
    - https://cwe.mitre.org/data/definitions/78.html

sources:    [ <pattern>, ... ]       # where taint enters        (required, >= 1)
sinks:      [ <pattern>, ... ]       # where taint is dangerous  (required, >= 1)
sanitizers: [ <pattern>, ... ]       # what neutralizes taint    (optional)
propagators:[ <propagator>, ... ]    # how taint flows through   (optional)
```

### Top-level fields

| Field | Required | Notes |
|---|---|---|
| `id` | yes | Globally unique. Convention: `<language>.<class>.<name>`. |
| `name` | yes | Short human-readable title. |
| `cwe` | yes | Primary CWE identifier; must match `CWE-<digits>` (e.g. `CWE-78`). |
| `severity` | yes | One of `low`, `medium`, `high`, `critical` (lowercase strings). |
| `languages` | yes | Non-empty list; `python` is the only supported value in v1 (P7). |
| `message` | yes | Explains the flaw **and** the fix; rendered on every finding. |
| `metadata` | no | Free-form map (`owasp`, `references`, …); document order is preserved. |
| `sources` | yes | One or more patterns. |
| `sinks` | yes | One or more patterns. |
| `sanitizers` | no | Optional; may be `[]`. A missing sanitizer never raises (P5). |
| `propagators` | no | Optional. Defaults to the engine's built-in propagation. |

Any **unknown** top-level key is rejected. Required keys must be present; the
parser reports the first offending key in document order (deterministic, P3).

---

## Validation & errors

`scanipy.dsl.parse_spec` validates every field shape, enum, and pattern/flow
grammar, and rejects anything outside the DSL (unknown keys/kinds, bad enums,
malformed patterns or flows, empty `sources`/`sinks`). Validation is exhaustive
and **declarative** (P4): there is no per-detector or per-CWE logic in the parser.

On any problem it raises a `scanipy.dsl.DSLError` (a `ValueError` subclass) whose
`str()` is a single, deterministic line:

```
path:line:col: [spec_id] field: message
```

for example:

```
detectors/injection/os-command.yml:29:5: [python.injection.os-command] sinks[1].when: unknown 'when' condition 'argument'; v1 supports: keyword
```

The error also exposes the raw pieces as attributes (`.spec_id`, `.field`,
`.source_path`, `.line`, `.column`) for programmatic use. Lines are 1-based and
columns 0-based. Invalid YAML and structural problems (empty document,
non-mapping root, duplicate keys) are reported the same way — a raw `yaml`
exception never escapes.

---

## Patterns

A **pattern** matches a syntactic site. It has a `kind`, a dotted `pattern`
string (with `*` wildcards), and optional constraints.

```yaml
{ kind: call, pattern: "os.system", args: [0] }
{ kind: attribute, pattern: "flask.request.*" }
{ kind: call, pattern: "subprocess.*", when: { keyword: { shell: true } } }
```

### `kind`

| `kind` | Matches | Pattern shape | Status |
|---|---|---|---|
| `call` | a function/method call, e.g. `os.system(...)` | dotted path, `*` wildcards | supported |
| `attribute` | an attribute access, e.g. `flask.request.args` | dotted path, `*` wildcards | supported |
| `parameter` | a function parameter (request-handler args) | a bare name (`request`) or a scoped selector (`handler.request`) | supported |
| `import` | an imported module/name | a module path, optionally ending in `*` (`pickle`, `flask.*`) | supported |

All four kinds share the same dotted-path grammar (see [`pattern`](#pattern)).
The parser validates pattern **shape** for every kind; the runtime meaning of
`parameter`/`import` is resolved by the engine. `args` and `when` are accepted
**only** on `kind: call` — see the validity matrix below.

### `pattern`

A dotted path with `*` as a wildcard segment:

- `os.system` — exactly `os.system`
- `subprocess.*` — any direct attribute of `subprocess` (`run`, `Popen`, …)
- `*.cursor.execute` — `execute` on any object's `.cursor`

### Optional constraints

| Key | Valid on | Meaning |
|---|---|---|
| `args` | `call` only | Restrict to specific **positional** argument indices, e.g. `args: [0]`. A non-empty list of non-negative integers; the parser sorts and de-duplicates them. Taint in any listed argument triggers the rule. |
| `when` | `call` only | Extra conditions. v0 supports exactly `when: { keyword: { name: value } }` — e.g. require `shell=True`. The `name` must be a valid identifier and the `value` must be a scalar. |

### `args` / `when` validity matrix

`args` and `when` are accepted **only** on `kind: call`; the parser rejects them
on `attribute`, `parameter`, and `import` with a precise error.

| `kind` | `args` | `when` |
|---|---|---|
| `call` | allowed | allowed |
| `attribute` | rejected | rejected |
| `parameter` | rejected | rejected |
| `import` | rejected | rejected |

Scalar typing is exact: `shell: true` is a YAML boolean and stays a `bool`,
while `shell: 'true'` stays the string `"true"`. The two are kept distinct so the
engine's `shell=True` check is unambiguous.

---

## Propagators

A **propagator** describes how taint moves through an intermediate call, using a
`flow` from one position to another. A propagator is a `kind: call` pattern (only
`call` is allowed) plus a **required** `flow` mapping with exactly the keys
`from` and `to`.

```yaml
propagators:
  - { kind: call, pattern: "str.format", flow: { from: any-arg, to: return } }
  - { kind: call, pattern: "os.path.join", flow: { from: any-arg, to: return } }
```

### Flow vocabulary

`from` and `to` each take exactly one token from the grammar below; anything else
(e.g. `returns`, `arg:x`, an empty string) is rejected.

| Token | Meaning |
|---|---|
| `any-arg` | any positional argument |
| `arg:N` | the Nth positional argument (0-based, `N` a non-negative integer) |
| `self` | the receiver of a method call |
| `return` | the call's return value |

The YAML key `from` maps to the `Flow.from_` field (Python keyword). The engine
ships with sensible default propagation (e.g. string concatenation and f-strings
carry taint); propagators add library-specific flows.

---

## Sanitizers and soundness (P5)

A **sanitizer** removes taint. Sanitizers are trusted in the **safe direction
only**: if scanipy is *missing* a sanitizer it will at worst report a false
positive (noise) — it must never *silently suppress a real vulnerability*. When
in doubt, leave a sanitizer out. This one-sidedness is principle **P5**.

Note that some "fixes" are not sanitizers of a string at all. For SQL injection,
the fix is a **bound-parameter call** (a different, safe sink), not a function
that cleans the string — so the SQL detector ships with no string sanitizers.

---

## Every detector ships a TP and a TN fixture (P5)

A spec is not done until it has both:

- a **true-positive** fixture (vulnerable code it **must** flag), and
- a **true-negative** fixture (safe/sanitized code it **must not** flag),

under `tests/fixtures/python/{vulnerable,safe}/`. See
[writing-detectors.md](writing-detectors.md) and the `/new-detector` helper.

---

## Worked example

```yaml
id: python.injection.os-command
name: OS command injection
cwe: CWE-78
severity: high
languages: [python]
message: >
  Untrusted input reaches an OS command without sanitization. Prefer a list
  argv with shell=False, or quote inputs with shlex.quote.
sources:
  - { kind: call, pattern: "input" }
  - { kind: attribute, pattern: "flask.request.*" }
sanitizers:
  - { kind: call, pattern: "shlex.quote" }
sinks:
  - { kind: call, pattern: "os.system", args: [0] }
  - { kind: call, pattern: "subprocess.*", when: { keyword: { shell: true } } }
propagators:
  - { kind: call, pattern: "str.format", flow: { from: any-arg, to: return } }
```
