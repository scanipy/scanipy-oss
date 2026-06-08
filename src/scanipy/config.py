# SPDX-License-Identifier: Apache-2.0
"""Layered scan configuration (defaults < file < CLI).

scanipy is zero-config by design (principle **P6**): every option has a sensible
default and a bare ``scanipy scan .`` works with no config file at all. A config
file is optional and only pins defaults.

This module discovers and validates an on-disk config and exposes the building
blocks the CLI uses to merge it with command-line flags:

* :func:`load_file_config` reads a discovered ``.scanipy.yml`` or
  ``[tool.scanipy]`` table from ``pyproject.toml`` into a normalized, validated
  :class:`dict`.
* :func:`merge_config` layers ``defaults < file < cli`` into a frozen
  :class:`ScanConfig`.
* :func:`load_config` is a convenience wrapper that discovers + merges (used by
  callers that do not need click parameter-source precedence).

Any unknown key or bad enum raises :class:`ConfigError`; the CLI maps that to
exit code ``2`` (P3: deterministic, fail-loud).

The ``[tool.scanipy]`` table in ``pyproject.toml`` requires Python 3.11+
(``tomllib`` is stdlib only from 3.11); on 3.10 it is silently skipped and only
``.scanipy.yml`` is honored (honest scope, P7).
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

from scanipy.models import Severity


def _import_tomllib() -> ModuleType | None:
    """Return the stdlib ``tomllib`` module, or ``None`` on Python 3.10.

    ``tomllib`` is stdlib only from Python 3.11. On 3.10 it is absent and the
    ``[tool.scanipy]`` table in ``pyproject.toml`` is silently unsupported (P7);
    ``.scanipy.yml`` still works everywhere. The import is done dynamically so the
    package imports cleanly on 3.10 (and mypy, which targets 3.10, stays happy).
    """
    try:
        return importlib.import_module("tomllib")
    except ModuleNotFoundError:  # pragma: no cover - exercised only on 3.10
        return None


_tomllib = _import_tomllib()

_FORMATS = ("text", "json", "sarif")

# Config-file keys map onto :class:`ScanConfig` fields. Order is the document
# order used when reporting the first offending key (P3).
_KNOWN_KEYS = (
    "detectors",
    "severity_threshold",
    "fail_on",
    "exclude",
    "output_format",
    "gitignore",
)

_CONFIG_FILENAME = ".scanipy.yml"
_PYPROJECT_FILENAME = "pyproject.toml"


class ConfigError(ValueError):
    """A config file is present but invalid (unknown key, bad enum, bad type).

    The CLI catches this and exits with code ``2``. ``str(self)`` is a single,
    deterministic, human-readable line.
    """


@dataclass(frozen=True)
class ScanConfig:
    """Resolved scan options after merging defaults < file < CLI."""

    detectors: tuple[str, ...] = ()
    severity_threshold: Severity = Severity.LOW
    fail_on: Severity | None = None
    exclude: tuple[str, ...] = ()
    output_format: str = "text"
    gitignore: bool = True


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def find_config_file(start: Path) -> Path | None:
    """Locate a config source near ``start`` (a scan root or its parent dir).

    Looks in ``start`` (if it is a directory) or in ``start.parent`` (if it is a
    file) for ``.scanipy.yml`` first, then a ``pyproject.toml`` that carries a
    ``[tool.scanipy]`` table. Discovery is shallow and deterministic — it does
    **not** walk parent directories (P3/P6: predictable zero-config behavior).
    Returns ``None`` when nothing is found.
    """
    base = start if start.is_dir() else start.parent
    candidate = base / _CONFIG_FILENAME
    if candidate.is_file():
        return candidate
    pyproject = base / _PYPROJECT_FILENAME
    if pyproject.is_file() and _pyproject_has_scanipy_table(pyproject):
        return pyproject
    return None


def _pyproject_has_scanipy_table(path: Path) -> bool:
    if _tomllib is None:  # pragma: no cover - 3.10 only
        return False
    try:
        data = _tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    tool = data.get("tool")
    return isinstance(tool, Mapping) and "scanipy" in tool


# ---------------------------------------------------------------------------
# Loading + validation
# ---------------------------------------------------------------------------


def load_file_config(path: str | Path) -> dict[str, Any]:
    """Read and validate a config file into a normalized mapping.

    ``path`` may be a ``.scanipy.yml`` (YAML root mapping) or a ``pyproject.toml``
    (``[tool.scanipy]`` table). Returns a dict whose keys are a subset of
    :data:`_KNOWN_KEYS` with values already coerced to the
    :class:`ScanConfig`-shaped Python types. Raises :class:`ConfigError` on any
    unknown key, bad enum, or wrong type.
    """
    p = Path(path)
    raw = _read_raw(p)
    return _validate(raw, source=str(p))


def _read_raw(path: Path) -> Mapping[str, Any]:
    if path.name == _PYPROJECT_FILENAME:
        if _tomllib is None:  # pragma: no cover - 3.10 only
            return {}
        try:
            data = _tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"{path}: could not read pyproject.toml: {exc}") from exc
        table = data.get("tool", {})
        scanipy_table = table.get("scanipy", {}) if isinstance(table, Mapping) else {}
        if not isinstance(scanipy_table, Mapping):
            raise ConfigError(f"{path}: [tool.scanipy] must be a table")
        return scanipy_table
    # .scanipy.yml (or any YAML config)
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"{path}: could not read config: {exc}") from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, Mapping):
        raise ConfigError(f"{path}: config root must be a mapping, got {type(loaded).__name__}")
    return loaded


def _validate(raw: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    # Report the first unknown key in document order for determinism (P3).
    for key in raw:
        if key not in _KNOWN_KEYS:
            allowed = ", ".join(_KNOWN_KEYS)
            raise ConfigError(f"{source}: unknown config key {key!r}; allowed keys: {allowed}")

    out: dict[str, Any] = {}
    if "detectors" in raw:
        out["detectors"] = _as_str_tuple(raw["detectors"], key="detectors", source=source)
    if "exclude" in raw:
        out["exclude"] = _as_str_tuple(raw["exclude"], key="exclude", source=source)
    if "severity_threshold" in raw:
        out["severity_threshold"] = _as_severity(
            raw["severity_threshold"], key="severity_threshold", source=source
        )
    if "fail_on" in raw:
        value = raw["fail_on"]
        if value is None:
            out["fail_on"] = None
        else:
            out["fail_on"] = _as_severity(value, key="fail_on", source=source)
    if "output_format" in raw:
        out["output_format"] = _as_format(raw["output_format"], source=source)
    if "gitignore" in raw:
        out["gitignore"] = _as_bool(raw["gitignore"], key="gitignore", source=source)
    return out


def _as_str_tuple(value: Any, *, key: str, source: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise ConfigError(f"{source}: {key!r} must be a list of strings")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigError(f"{source}: {key!r} entries must be strings, got {item!r}")
        items.append(item)
    return tuple(items)


def _as_severity(value: Any, *, key: str, source: str) -> Severity:
    if not isinstance(value, str):
        raise ConfigError(f"{source}: {key!r} must be one of {_severity_choices()}, got {value!r}")
    try:
        return Severity.from_str(value)
    except ValueError as exc:
        raise ConfigError(
            f"{source}: {key!r} must be one of {_severity_choices()}, got {value!r}"
        ) from exc


def _as_format(value: Any, *, source: str) -> str:
    if not isinstance(value, str) or value not in _FORMATS:
        allowed = ", ".join(_FORMATS)
        raise ConfigError(f"{source}: 'output_format' must be one of {allowed}, got {value!r}")
    return value


def _as_bool(value: Any, *, key: str, source: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{source}: {key!r} must be a boolean, got {value!r}")
    return value


def _severity_choices() -> str:
    return ", ".join(s.value for s in Severity)


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


def merge_config(
    file_config: Mapping[str, Any] | None = None,
    cli_overrides: Mapping[str, Any] | None = None,
) -> ScanConfig:
    """Layer ``defaults < file < CLI`` into a frozen :class:`ScanConfig`.

    ``cli_overrides`` must contain **only** values the user actually set on the
    command line (the caller filters by click's parameter source); ``None`` values
    are ignored so an unset flag never clobbers a file value.
    """
    config = ScanConfig()
    if file_config:
        config = replace(config, **dict(file_config))
    if cli_overrides:
        applied = {k: v for k, v in cli_overrides.items() if v is not None}
        if applied:
            config = replace(config, **applied)
    return config


def load_config(path: str | Path | None = None) -> ScanConfig:
    """Discover + load a config into a :class:`ScanConfig` (no CLI overlay).

    With an explicit ``path`` that file is loaded; otherwise discovery starts at
    the current directory. Missing config yields defaults (zero-config, P6). For
    full ``defaults < file < CLI`` precedence the CLI uses :func:`load_file_config`
    + :func:`merge_config` directly with click parameter sources.
    """
    if path is not None:
        return merge_config(load_file_config(path))
    discovered = find_config_file(Path.cwd())
    if discovered is None:
        return ScanConfig()
    return merge_config(load_file_config(discovered))
