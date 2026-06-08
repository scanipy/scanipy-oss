# End-to-end example

This walks one detector — `python.injection.os-command` (CWE-78) — from a
vulnerable file, through the exact witness-backed finding `scanipy scan` prints,
to the safe counterpart that produces nothing. The terminal output below is
captured from the **real CLI** and is verified byte-for-byte by
`tests/docs/test_end_to_end_example.py`, so what you read here is what the tool
prints.

> All commands are run from the repository root, and the paths shown
> (`tests/fixtures/python/...`) are the relative paths passed on the command
> line — scanipy echoes paths exactly as given.

## 1. The vulnerable fixture

[`tests/fixtures/python/vulnerable/os-command.py`](../../tests/fixtures/python/vulnerable/os-command.py):

```python
# SPDX-License-Identifier: Apache-2.0
# Intentionally vulnerable fixture for detector `python.injection.os-command`.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports a CWE-78 finding (input() -> os.system, no sanitizer).
import os


def main() -> None:
    name = input("name: ")          # taint source
    os.system("echo " + name)       # dangerous sink: OS command injection
```

Untrusted data from `input()` (line 9) flows — through string concatenation,
which the engine treats as a default propagator — into `os.system` (line 10)
with no sanitizer in between. That is exactly the source → sink shape the
detector looks for.

## 2. Scanning it — the finding

```console
$ scanipy scan tests/fixtures/python/vulnerable/os-command.py
HIGH python.injection.os-command [CWE-78] tests/fixtures/python/vulnerable/os-command.py:10:4
    Untrusted input reaches an OS command without sanitization, allowing an attacker to execute arbitrary commands. Prefer a list argv with shell=False, or quote inputs with shlex.quote.

    - source: tests/fixtures/python/vulnerable/os-command.py:9:11  source input
    - sink: tests/fixtures/python/vulnerable/os-command.py:10:4  sink os.system

1 finding.
```

Reading the report top to bottom:

- **Header** — `HIGH` severity, the detector id `python.injection.os-command`,
  the CWE (`[CWE-78]`), and the **sink** location (`...os-command.py:10:4`).
- **Message** — what the flaw is *and* how to fix it.
- **Witness** — the `source → … → sink` trace (principle P2). Here it is a
  two-step path: the `source` at `9:11` (`input`) and the `sink` at `10:4`
  (`os.system`). Every finding carries this trace, so you see *why* it fired.

The process **exits `1`** because a finding met the failure gate:

```console
$ echo $?
1
```

## 3. The safe counterpart — no finding

[`tests/fixtures/python/safe/os-command.py`](../../tests/fixtures/python/safe/os-command.py)
fixes the bug by avoiding the shell entirely and quoting the value:

```python
# SPDX-License-Identifier: Apache-2.0
# Intentionally SAFE counterpart to the os-command injection fixture.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports NO finding (no shell, and the input is quoted).
import shlex
import subprocess


def main() -> None:
    name = input("name: ")                              # taint source
    subprocess.run(["echo", shlex.quote(name)], check=True)  # safe: no shell, quoted
```

`subprocess.run([...])` is a list-argv call with no `shell=True`, so the
`subprocess.*` sink does not match, and `shlex.quote` sanitizes the value anyway.
The scan is clean:

```console
$ scanipy scan tests/fixtures/python/safe/os-command.py
No findings.
```

And it **exits `0`**:

```console
$ echo $?
0
```

## Exit codes at a glance

| Result | stdout | Exit code |
|---|---|---|
| Vulnerable fixture (finding meets the gate) | the witness-backed finding above | `1` |
| Safe fixture (clean) | `No findings.` | `0` |

(`2` is reserved for a fatal or usage error — a bad path, invalid config, an
unknown `--detectors` id, an unknown `rules show` id, or a `rules validate`
failure.) See [usage.md](../usage.md#exit-codes) for the full table.
