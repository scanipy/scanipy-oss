# SPDX-License-Identifier: Apache-2.0
"""scanipy command-line interface.

Status: 0.1.0 scaffold. ``scanipy --help``, ``scanipy --version``, and
``scanipy version`` work today. ``scan`` and ``rules`` are wired into the CLI
but not yet implemented — they print a notice and exit with
:attr:`~scanipy.exit_codes.ExitCode.ERROR` (2). The ``cli-ux`` and
``taint-engine`` agents fill these in.
"""

from __future__ import annotations

from typing import NoReturn

import click

from scanipy import __version__
from scanipy.exit_codes import ExitCode

_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}
_REPO_URL = "https://github.com/scanipy/scanipy-oss"

_FORMATS = ("text", "json", "sarif")
_SEVERITIES = ("low", "medium", "high", "critical")


def _not_implemented(feature: str) -> NoReturn:
    """Report a stubbed command and exit with ``ExitCode.ERROR``."""
    click.echo(
        f"\N{CONSTRUCTION SIGN}  `{feature}` is not implemented yet in scanipy {__version__}.",
        err=True,
    )
    click.echo(f"   This is an early scaffold — follow {_REPO_URL} for progress.", err=True)
    raise SystemExit(int(ExitCode.ERROR))


@click.group(context_settings=_CONTEXT_SETTINGS, no_args_is_help=True)
@click.version_option(__version__, "-V", "--version", prog_name="scanipy")
def cli() -> None:
    """scanipy — local, private, taint-tracking SAST for your code.

    Point scanipy at a path and it follows untrusted input from sources to
    dangerous sinks, reporting the data-flow trace behind every finding.
    """


@cli.command()
@click.argument("path", type=click.Path(exists=True, file_okay=True, dir_okay=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(_FORMATS),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--detectors",
    "detectors",
    multiple=True,
    metavar="ID",
    help="Limit to specific detector ids (repeatable).",
)
@click.option(
    "--severity-threshold",
    type=click.Choice(_SEVERITIES),
    default="low",
    show_default=True,
    help="Ignore findings below this severity.",
)
@click.option(
    "--fail-on",
    type=click.Choice(_SEVERITIES),
    default=None,
    help="Exit non-zero only when a finding at/above this severity is reported.",
)
@click.option(
    "--exclude",
    "exclude",
    multiple=True,
    metavar="GLOB",
    help="Glob of paths to skip (repeatable).",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to a scanipy config file.",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Write results to a file instead of stdout.",
)
def scan(
    path: str,
    output_format: str,
    detectors: tuple[str, ...],
    severity_threshold: str,
    fail_on: str | None,
    exclude: tuple[str, ...],
    config_path: str | None,
    output_path: str | None,
) -> None:
    """Scan PATH for vulnerabilities using taint analysis."""
    _not_implemented("scan")


@cli.group()
def rules() -> None:
    """Inspect and validate detector specs."""


@rules.command("list")
def rules_list() -> None:
    """List the bundled detector specs."""
    _not_implemented("rules list")


@rules.command("show")
@click.argument("detector_id")
def rules_show(detector_id: str) -> None:
    """Show one detector spec by id."""
    _not_implemented("rules show")


@rules.command("validate")
@click.argument("spec_file", type=click.Path(exists=True, dir_okay=False))
def rules_validate(spec_file: str) -> None:
    """Validate a detector spec file against the taint DSL."""
    _not_implemented("rules validate")


@cli.command()
def version() -> None:
    """Print the scanipy version."""
    click.echo(f"scanipy {__version__}")


def main() -> None:
    """Console-script entry point (the ``scanipy`` command)."""
    cli()
