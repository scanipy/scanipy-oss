# Security Policy

Thanks for helping keep **scanipy** (the open-source edition) safe. scanipy is a
local, private, zero-config taint-tracking SAST CLI for Python. This document
explains how to report a vulnerability **in scanipy the tool itself**.

> [!IMPORTANT]
> **Scope — read this first.**
> This policy is for vulnerabilities **in scanipy the tool** (the CLI, the engine,
> the detector loader, our packaging, etc.).
>
> It is **not** for vulnerabilities that scanipy *reports in your own code*. If
> scanipy flagged a finding in your project, that's an issue in your project, not
> in scanipy — please fix it there. (And if you think a finding is a false
> positive or a false negative, that's a regular bug/quality report, not a
> security report — open a normal GitHub issue.)

## Supported versions

scanipy is early (version `0.1.0`). We currently support security fixes for the
latest `0.1.x` release line only.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

As the project matures this table will grow. Until then, please make sure you're
on the latest `0.1.x` (`pip install --upgrade scanipy-oss`) before reporting.

## Reporting a vulnerability

**Please do not open a public issue for security problems.** Report privately so
we can fix the issue before it's widely known.

Preferred channel:

- **GitHub private security advisories.** Go to
  <https://github.com/scanipy/scanipy-oss> → **Security** → **Report a
  vulnerability**. This keeps the report private and lets us collaborate on a fix
  and a coordinated release.

Fallback channel:

- **Email:** `security@scanipy.com` — the GitHub private advisory flow above is
  preferred, but this address works too.

When you report, it helps a lot if you can include:

- the scanipy version (`scanipy version`) and how you installed it;
- your Python version and OS;
- a minimal reproduction (a small input, the command you ran, and what happened);
- the impact as you understand it.

## What to expect

We're a small open-source project, so please set expectations accordingly:

- **Acknowledgement:** we aim to acknowledge a report within **5 business days**.
- **Triage & updates:** we'll let you know whether we can reproduce it and keep
  you posted as we work on a fix.

These are good-faith targets for an early-stage project, not a contractual SLA.

## Coordinated disclosure

We follow **coordinated (responsible) disclosure**:

- Please give us a reasonable chance to investigate and ship a fix before any
  public disclosure. As a default we suggest **90 days** from your report, or
  until a fix is released — whichever comes first — and we're happy to coordinate
  timing with you.
- We'll work with you on the fix, the release, and an advisory.
- With your permission, we're glad to credit you in the advisory and release
  notes. If you'd prefer to stay anonymous, just say so.
- Please don't access or modify other people's data, degrade the service, or run
  tests against systems you don't own while researching. scanipy runs locally and
  never sends your code over the network, so good-faith testing should stay on
  your own machine and your own code.

Thank you for reporting responsibly.
