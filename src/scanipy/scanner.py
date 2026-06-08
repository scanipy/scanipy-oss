# SPDX-License-Identifier: Apache-2.0
"""Scan orchestrator — wire discovery, frontend, engine, and reporting together.

:func:`run_scan` is the single entry point the CLI delegates to. It:

1. discovers the ``*.py`` files under the scan path (:mod:`scanipy.discovery`);
2. parses + analyzes each file in **isolation** — one unparsable or crashing file
   is reported to ``parse_errors`` and never aborts the run;
3. aggregates findings, drops anything below the severity threshold, dedups, and
   sorts into a **total order** (P3);
4. computes the process exit code from the configured gate.

It performs **no network I/O** (P1) and no rendering — the CLI owns stdout/stderr
so the scanner stays testable and machine-clean.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from scanipy.config import ScanConfig
from scanipy.discovery import discover_python_files
from scanipy.dsl import DetectorSpec
from scanipy.engine import TaintEngine
from scanipy.exit_codes import ExitCode
from scanipy.frontends.python_frontend import PythonFrontend
from scanipy.models import Finding, Severity


@dataclass(frozen=True)
class ParseError:
    """A file that could not be parsed or analyzed (reported, never fatal)."""

    path: Path
    reason: str


@dataclass(frozen=True)
class ScanResult:
    """The outcome of a scan: findings, parse errors, and the exit code."""

    findings: tuple[Finding, ...]
    parse_errors: tuple[ParseError, ...] = ()
    files_scanned: int = 0
    exit_code: ExitCode = ExitCode.OK
    diagnostics: tuple[str, ...] = field(default_factory=tuple)


def run_scan(
    path: str | Path,
    specs: Sequence[DetectorSpec],
    config: ScanConfig,
) -> ScanResult:
    """Discover, analyze, aggregate, and grade a scan over ``path``.

    ``specs`` is the (already-filtered) detector pack; ``config`` carries the
    resolved options (threshold, fail-on, excludes, gitignore). The returned
    :class:`ScanResult` holds the deterministically-ordered findings, any per-file
    parse errors, and the computed exit code.
    """
    files = discover_python_files(
        path,
        exclude=config.exclude,
        use_gitignore=config.gitignore,
    )

    engine = TaintEngine(specs)
    frontend = PythonFrontend()

    raw: list[Finding] = []
    parse_errors: list[ParseError] = []
    scanned = 0

    for file in files:
        module = _safe_parse(frontend, file, parse_errors)
        if module is None:
            continue
        try:
            raw.extend(engine.analyze(module))
            scanned += 1
        except Exception as exc:  # per-file isolation: one bad file never aborts the run
            parse_errors.append(ParseError(path=file, reason=f"analysis failed: {exc}"))

    findings = aggregate(raw, config.severity_threshold)
    exit_code = compute_exit_code(findings, config)

    diagnostics = tuple(f"{err.path}: {err.reason}" for err in parse_errors)
    return ScanResult(
        findings=findings,
        parse_errors=tuple(parse_errors),
        files_scanned=scanned,
        exit_code=exit_code,
        diagnostics=diagnostics,
    )


def _safe_parse(
    frontend: PythonFrontend,
    file: Path,
    parse_errors: list[ParseError],
) -> object | None:
    """Parse one file, capturing any failure as a non-fatal parse error."""
    try:
        module = frontend.parse(file)
    except Exception as exc:  # frontend should return None, but never trust it to
        parse_errors.append(ParseError(path=file, reason=f"parse failed: {exc}"))
        return None
    if module is None:
        parse_errors.append(ParseError(path=file, reason="could not parse (syntax/encoding error)"))
        return None
    return module


# ---------------------------------------------------------------------------
# Aggregation: severity filter + dedup + total-order sort (P3)
# ---------------------------------------------------------------------------


def aggregate(findings: Sequence[Finding], threshold: Severity) -> tuple[Finding, ...]:
    """Filter below ``threshold``, dedup, and sort into a total order (P3).

    Dedup uses the engine's documented key — ``(detector_id, sink location,
    source-start location)`` — collapsing the same vulnerability discovered via
    overlapping patterns or across the per-file passes. The final sort key is
    ``(file, line, column, detector_id, fingerprint)`` so the order is total even
    when two findings share a location and detector id.
    """
    kept = [f for f in findings if f.severity.rank >= threshold.rank]

    seen: set[tuple[str, ...]] = set()
    deduped: list[Finding] = []
    for finding in sorted(kept, key=_sort_key):
        key = _dedup_key(finding)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return tuple(deduped)


def _sort_key(finding: Finding) -> tuple[str, int, int, str, str]:
    loc = finding.location
    return (
        loc.file,
        loc.line,
        loc.column,
        finding.detector_id,
        finding.fingerprint or "",
    )


def _dedup_key(finding: Finding) -> tuple[str, ...]:
    sink = finding.location
    source_loc = finding.witness[0].location if finding.witness else sink
    return (
        finding.detector_id,
        sink.file,
        str(sink.line),
        str(sink.column),
        source_loc.file,
        str(source_loc.line),
        str(source_loc.column),
    )


# ---------------------------------------------------------------------------
# Exit code
# ---------------------------------------------------------------------------


def compute_exit_code(findings: Sequence[Finding], config: ScanConfig) -> ExitCode:
    """Exit ``1`` iff a (post-filter) finding meets the gate, else ``0``.

    The gate is ``fail_on`` when set, otherwise the severity threshold. With no
    ``fail_on`` and the default ``low`` threshold this means "any reported finding
    fails the run", matching the CLI's documented behavior.
    """
    gate = config.fail_on if config.fail_on is not None else config.severity_threshold
    if any(f.severity.rank >= gate.rank for f in findings):
        return ExitCode.FINDINGS
    return ExitCode.OK
