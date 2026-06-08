# SPDX-License-Identifier: Apache-2.0
"""scanipy command-line interface.

A thin click layer over the scan pipeline: ``scan`` discovers files, runs taint
analysis, and renders findings; ``rules list/show/validate`` inspect the detector
catalog. Detection logic and orchestration live in :mod:`scanipy.scanner`,
:mod:`scanipy.config`, and :mod:`scanipy.registry` — this module only parses flags,
applies CLI > file > defaults precedence, writes output, and maps results to exit
codes (P3, P6).

Exit codes (P3): ``0`` clean, ``1`` a finding met the fail gate, ``2`` a fatal or
usage error (bad path, invalid config, unknown rule id, validation failure).
Per-file parse errors are **not** fatal — they go to stderr and the run continues.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import click

from scanipy import __version__
from scanipy.config import ConfigError, ScanConfig, find_config_file, load_file_config, merge_config
from scanipy.dsl import DetectorSpec, DSLError, Pattern, load_spec_file
from scanipy.exit_codes import ExitCode
from scanipy.models import Severity
from scanipy.registry import (
    UnknownDetectorError,
    load_builtin_detectors,
    load_detector_specs,
)
from scanipy.reporting import get_reporter
from scanipy.scanner import run_scan

_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

_FORMATS = ("text", "json", "sarif")
_SEVERITIES = ("low", "medium", "high", "critical")


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
    "--gitignore/--no-gitignore",
    "gitignore",
    default=True,
    show_default=True,
    help="Honor the scan-root .gitignore.",
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
@click.pass_context
def scan(
    ctx: click.Context,
    path: str,
    output_format: str,
    detectors: tuple[str, ...],
    severity_threshold: str,
    fail_on: str | None,
    exclude: tuple[str, ...],
    gitignore: bool,
    config_path: str | None,
    output_path: str | None,
) -> None:
    """Scan PATH for vulnerabilities using taint analysis."""
    config = _resolve_config(
        ctx,
        path=path,
        config_path=config_path,
        output_format=output_format,
        detectors=detectors,
        severity_threshold=severity_threshold,
        fail_on=fail_on,
        exclude=exclude,
        gitignore=gitignore,
    )

    try:
        specs = load_detector_specs(config.detectors)
    except UnknownDetectorError as exc:
        click.echo(f"error: {exc}", err=True)
        click.echo(f"available detectors: {', '.join(exc.available)}", err=True)
        raise SystemExit(int(ExitCode.ERROR)) from exc
    except DSLError as exc:
        click.echo(f"error: invalid bundled detector: {exc}", err=True)
        raise SystemExit(int(ExitCode.ERROR)) from exc

    result = run_scan(path, specs, config)

    # Per-file parse errors go to stderr only; stdout stays machine-clean.
    for diagnostic in result.diagnostics:
        click.echo(f"warning: skipped {diagnostic}", err=True)

    rendered = get_reporter(config.output_format).render(result.findings)
    _emit(rendered, output_path)

    raise SystemExit(int(result.exit_code))


def _resolve_config(
    ctx: click.Context,
    *,
    path: str,
    config_path: str | None,
    output_format: str,
    detectors: tuple[str, ...],
    severity_threshold: str,
    fail_on: str | None,
    exclude: tuple[str, ...],
    gitignore: bool,
) -> ScanConfig:
    """Layer defaults < file < CLI using click's parameter source (P3)."""
    try:
        file_config = _load_file_config(config_path, path)
    except ConfigError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(int(ExitCode.ERROR)) from exc

    overrides: dict[str, object] = {}
    if _from_cli(ctx, "output_format"):
        overrides["output_format"] = output_format
    if _from_cli(ctx, "detectors") and detectors:
        overrides["detectors"] = tuple(detectors)
    if _from_cli(ctx, "severity_threshold"):
        overrides["severity_threshold"] = Severity.from_str(severity_threshold)
    if fail_on is not None:
        overrides["fail_on"] = Severity.from_str(fail_on)
    if _from_cli(ctx, "exclude") and exclude:
        overrides["exclude"] = tuple(exclude)
    if _from_cli(ctx, "gitignore"):
        overrides["gitignore"] = gitignore

    return merge_config(file_config, overrides)


def _load_file_config(config_path: str | None, scan_path: str) -> dict[str, object]:
    """Read an explicit ``--config`` file, else auto-discover one near the scan root."""
    if config_path is not None:
        return load_file_config(config_path)
    discovered = find_config_file(Path(scan_path))
    if discovered is None:
        return {}
    return load_file_config(discovered)


def _from_cli(ctx: click.Context, param: str) -> bool:
    """True when ``param`` was set on the command line / env, not defaulted."""
    source = ctx.get_parameter_source(param)
    if source is None:
        return False
    return source.name in {"COMMANDLINE", "ENVIRONMENT", "PROMPT"}


def _emit(rendered: str, output_path: str | None) -> None:
    if output_path is None:
        click.echo(rendered)
        return
    Path(output_path).write_text(rendered + "\n", encoding="utf-8")


@cli.group()
def rules() -> None:
    """Inspect and validate detector specs."""


@rules.command("list")
def rules_list() -> None:
    """List the bundled detector specs (sorted by id)."""
    specs = load_builtin_detectors()
    for spec in specs:
        click.echo(f"{spec.id}  [{spec.cwe}]  {spec.severity.value}  {spec.name}")


@rules.command("show")
@click.argument("detector_id")
def rules_show(detector_id: str) -> None:
    """Show one detector spec by id."""
    specs = load_builtin_detectors()
    match = next((s for s in specs if s.id == detector_id), None)
    if match is None:
        click.echo(f"error: unknown detector id {detector_id!r}", err=True)
        click.echo("available detectors:", err=True)
        for spec in specs:
            click.echo(f"  {spec.id}", err=True)
        raise SystemExit(int(ExitCode.ERROR))
    click.echo(_render_spec(match))


def _render_spec(spec: DetectorSpec) -> str:
    lines: list[str] = [
        f"id:        {spec.id}",
        f"name:      {spec.name}",
        f"cwe:       {spec.cwe}",
        f"severity:  {spec.severity.value}",
        f"languages: {', '.join(spec.languages)}",
        f"message:   {spec.message.strip()}",
    ]

    def _pattern_body(p: Pattern) -> str:
        parts = [f"kind={p.kind.value}", f"pattern={p.pattern!r}"]
        if p.args is not None:
            parts.append(f"args={list(p.args)}")
        if p.when is not None:
            when = {str(k): dict(v) if isinstance(v, Mapping) else v for k, v in p.when.items()}
            parts.append(f"when={when}")
        return ", ".join(parts)

    def _section(title: str, patterns: tuple[Pattern, ...]) -> None:
        lines.append(f"{title}:")
        for p in patterns:
            lines.append(f"    - {_pattern_body(p)}")

    _section("sources", spec.sources)
    _section("sinks", spec.sinks)
    if spec.sanitizers:
        _section("sanitizers", spec.sanitizers)
    if spec.propagators:
        lines.append("propagators:")
        for prop in spec.propagators:
            flow = f"flow={{from: {prop.flow.from_}, to: {prop.flow.to}}}"
            lines.append(f"    - {_pattern_body(prop.pattern)}, {flow}")
    if spec.metadata:
        lines.append("metadata:")
        for key in sorted(spec.metadata):
            lines.append(f"    {key}: {spec.metadata[key]}")
    return "\n".join(lines)


@rules.command("validate")
@click.argument("spec_file", type=click.Path(exists=True, dir_okay=False))
def rules_validate(spec_file: str) -> None:
    """Validate a detector spec file against the taint DSL."""
    try:
        spec = load_spec_file(spec_file)
    except DSLError as exc:
        click.echo(str(exc), err=True)
        raise SystemExit(int(ExitCode.ERROR)) from exc
    click.echo(f"{spec_file}: valid ({spec.id})")


@cli.command()
def version() -> None:
    """Print the scanipy version."""
    click.echo(f"scanipy {__version__}")


def main() -> None:
    """Console-script entry point (the ``scanipy`` command)."""
    cli()
