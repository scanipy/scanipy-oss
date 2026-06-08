# SPDX-License-Identifier: Apache-2.0
"""Unit tests for layered scan configuration (CLI_1, CLI_2).

Covers discovery (.scanipy.yml + pyproject [tool.scanipy]), validation (unknown
keys, bad enums, bad types raise ConfigError), and the defaults < file < CLI
merge.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from scanipy.config import (
    ConfigError,
    ScanConfig,
    find_config_file,
    load_config,
    load_file_config,
    merge_config,
)
from scanipy.models import Severity


def test_defaults_are_zero_config() -> None:
    config = ScanConfig()
    assert config.detectors == ()
    assert config.severity_threshold is Severity.LOW
    assert config.fail_on is None
    assert config.exclude == ()
    assert config.output_format == "text"
    assert config.gitignore is True


def test_load_config_no_file_returns_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_config() == ScanConfig()


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_find_config_file_finds_scanipy_yml(tmp_path: Path) -> None:
    cfg = tmp_path / ".scanipy.yml"
    cfg.write_text("severity_threshold: high\n")
    assert find_config_file(tmp_path) == cfg


def test_find_config_file_for_file_path_uses_parent(tmp_path: Path) -> None:
    cfg = tmp_path / ".scanipy.yml"
    cfg.write_text("output_format: json\n")
    target = tmp_path / "code.py"
    target.write_text("x = 1\n")
    assert find_config_file(target) == cfg


def test_find_config_file_returns_none_when_absent(tmp_path: Path) -> None:
    assert find_config_file(tmp_path) is None


def test_find_config_does_not_walk_parents(tmp_path: Path) -> None:
    (tmp_path / ".scanipy.yml").write_text("output_format: json\n")
    child = tmp_path / "sub"
    child.mkdir()
    assert find_config_file(child) is None


def test_scanipy_yml_preferred_over_pyproject(tmp_path: Path) -> None:
    yml = tmp_path / ".scanipy.yml"
    yml.write_text("output_format: json\n")
    (tmp_path / "pyproject.toml").write_text("[tool.scanipy]\noutput_format = 'sarif'\n")
    assert find_config_file(tmp_path) == yml


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_load_file_config_parses_all_keys(tmp_path: Path) -> None:
    cfg = tmp_path / ".scanipy.yml"
    cfg.write_text(
        "detectors: [python.injection.os-command]\n"
        "severity_threshold: medium\n"
        "fail_on: high\n"
        "exclude: ['tests/*']\n"
        "output_format: json\n"
        "gitignore: false\n"
    )
    loaded = load_file_config(cfg)
    assert loaded["detectors"] == ("python.injection.os-command",)
    assert loaded["severity_threshold"] is Severity.MEDIUM
    assert loaded["fail_on"] is Severity.HIGH
    assert loaded["exclude"] == ("tests/*",)
    assert loaded["output_format"] == "json"
    assert loaded["gitignore"] is False


def test_empty_config_file_is_ok(tmp_path: Path) -> None:
    cfg = tmp_path / ".scanipy.yml"
    cfg.write_text("")
    assert load_file_config(cfg) == {}


def test_unknown_key_raises_config_error(tmp_path: Path) -> None:
    cfg = tmp_path / ".scanipy.yml"
    cfg.write_text("nope: 1\n")
    with pytest.raises(ConfigError, match="unknown config key 'nope'"):
        load_file_config(cfg)


def test_bad_severity_enum_raises(tmp_path: Path) -> None:
    cfg = tmp_path / ".scanipy.yml"
    cfg.write_text("severity_threshold: extreme\n")
    with pytest.raises(ConfigError, match="severity_threshold"):
        load_file_config(cfg)


def test_bad_format_raises(tmp_path: Path) -> None:
    cfg = tmp_path / ".scanipy.yml"
    cfg.write_text("output_format: yaml\n")
    with pytest.raises(ConfigError, match="output_format"):
        load_file_config(cfg)


def test_detectors_must_be_string_list(tmp_path: Path) -> None:
    cfg = tmp_path / ".scanipy.yml"
    cfg.write_text("detectors: 'just-a-string'\n")
    with pytest.raises(ConfigError, match="detectors"):
        load_file_config(cfg)


def test_gitignore_must_be_bool(tmp_path: Path) -> None:
    cfg = tmp_path / ".scanipy.yml"
    cfg.write_text("gitignore: maybe\n")
    with pytest.raises(ConfigError, match="gitignore"):
        load_file_config(cfg)


def test_non_mapping_root_raises(tmp_path: Path) -> None:
    cfg = tmp_path / ".scanipy.yml"
    cfg.write_text("- a\n- b\n")
    with pytest.raises(ConfigError, match="must be a mapping"):
        load_file_config(cfg)


@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib is 3.11+")
def test_pyproject_table_loads(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.scanipy]\nseverity_threshold = 'high'\nexclude = ['gen/*']\n")
    assert find_config_file(tmp_path) == pyproject
    loaded = load_file_config(pyproject)
    assert loaded["severity_threshold"] is Severity.HIGH
    assert loaded["exclude"] == ("gen/*",)


@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib is 3.11+")
def test_pyproject_unknown_key_raises(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.scanipy]\nbogus = 1\n")
    with pytest.raises(ConfigError, match="unknown config key 'bogus'"):
        load_file_config(pyproject)


def test_pyproject_without_scanipy_table_not_discovered(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.black]\nline-length = 88\n")
    assert find_config_file(tmp_path) is None


# ---------------------------------------------------------------------------
# Merge precedence: defaults < file < CLI
# ---------------------------------------------------------------------------


def test_merge_defaults_only() -> None:
    assert merge_config() == ScanConfig()


def test_merge_file_over_defaults() -> None:
    config = merge_config({"severity_threshold": Severity.HIGH, "output_format": "json"})
    assert config.severity_threshold is Severity.HIGH
    assert config.output_format == "json"
    # Untouched fields keep defaults.
    assert config.gitignore is True


def test_merge_cli_over_file() -> None:
    config = merge_config(
        {"severity_threshold": Severity.HIGH, "output_format": "json"},
        {"severity_threshold": Severity.LOW},
    )
    assert config.severity_threshold is Severity.LOW  # CLI wins
    assert config.output_format == "json"  # file kept where CLI is silent


def test_merge_ignores_none_cli_overrides() -> None:
    config = merge_config(
        {"output_format": "json"},
        {"output_format": None, "fail_on": Severity.HIGH},
    )
    assert config.output_format == "json"  # None did not clobber the file value
    assert config.fail_on is Severity.HIGH
