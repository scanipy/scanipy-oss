# SPDX-License-Identifier: Apache-2.0
"""Unit tests for file discovery (CLI_3, CLI_4).

Covers the *.py walk, default directory excludes, --exclude globs, .gitignore
honoring (and its --no-gitignore opt-out), and deterministic sorted order.
"""

from __future__ import annotations

from pathlib import Path

from scanipy.discovery import discover_python_files


def _names(paths: tuple[Path, ...], root: Path) -> list[str]:
    return [p.relative_to(root).as_posix() for p in paths]


def test_single_python_file_returned(tmp_path: Path) -> None:
    f = tmp_path / "mod.py"
    f.write_text("x = 1\n")
    assert discover_python_files(f) == (f,)


def test_single_non_python_file_skipped(tmp_path: Path) -> None:
    f = tmp_path / "data.txt"
    f.write_text("hello\n")
    assert discover_python_files(f) == ()


def test_walks_directory_for_py_only(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")
    (tmp_path / "readme.md").write_text("hi\n")
    found = discover_python_files(tmp_path)
    assert _names(found, tmp_path) == ["a.py", "b.py"]


def test_result_is_sorted_deterministically(tmp_path: Path) -> None:
    for name in ("zeta.py", "alpha.py", "mid.py"):
        (tmp_path / name).write_text("pass\n")
    found = discover_python_files(tmp_path)
    assert _names(found, tmp_path) == ["alpha.py", "mid.py", "zeta.py"]


def test_default_excludes_noise_dirs(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("pass\n")
    for noise in (".venv", ".git", "__pycache__", "build", "node_modules"):
        d = tmp_path / noise
        d.mkdir()
        (d / "junk.py").write_text("pass\n")
    found = discover_python_files(tmp_path)
    assert _names(found, tmp_path) == ["keep.py"]


def test_nested_directories_walked(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg" / "sub"
    pkg.mkdir(parents=True)
    (pkg / "deep.py").write_text("pass\n")
    (tmp_path / "top.py").write_text("pass\n")
    found = discover_python_files(tmp_path)
    assert _names(found, tmp_path) == ["pkg/sub/deep.py", "top.py"]


def test_exclude_glob_by_relative_path(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("pass\n")
    gen = tmp_path / "gen"
    gen.mkdir()
    (gen / "x.py").write_text("pass\n")
    found = discover_python_files(tmp_path, exclude=["gen/*"])
    assert _names(found, tmp_path) == ["keep.py"]


def test_exclude_glob_by_basename(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("pass\n")
    (tmp_path / "thing.gen.py").write_text("pass\n")
    found = discover_python_files(tmp_path, exclude=["*.gen.py"])
    assert _names(found, tmp_path) == ["keep.py"]


def test_exclude_directory_glob_prunes_subtree(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("pass\n")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "lib.py").write_text("pass\n")
    found = discover_python_files(tmp_path, exclude=["vendor"])
    assert _names(found, tmp_path) == ["keep.py"]


# ---------------------------------------------------------------------------
# .gitignore
# ---------------------------------------------------------------------------


def test_gitignore_honored_by_default(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("pass\n")
    (tmp_path / "ignored.py").write_text("pass\n")
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    found = discover_python_files(tmp_path)
    assert _names(found, tmp_path) == ["keep.py"]


def test_no_gitignore_opt_out(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("pass\n")
    (tmp_path / "ignored.py").write_text("pass\n")
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    found = discover_python_files(tmp_path, use_gitignore=False)
    assert _names(found, tmp_path) == ["ignored.py", "keep.py"]


def test_gitignore_directory_pattern(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("pass\n")
    out = tmp_path / "out"
    out.mkdir()
    (out / "x.py").write_text("pass\n")
    (tmp_path / ".gitignore").write_text("out/\n")
    found = discover_python_files(tmp_path)
    assert _names(found, tmp_path) == ["keep.py"]


def test_gitignore_comments_and_blanks_ignored(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("pass\n")
    (tmp_path / "skip.py").write_text("pass\n")
    (tmp_path / ".gitignore").write_text("# a comment\n\nskip.py\n")
    found = discover_python_files(tmp_path)
    assert _names(found, tmp_path) == ["keep.py"]


def test_gitignore_basename_at_any_depth(tmp_path: Path) -> None:
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "secret.py").write_text("pass\n")
    (tmp_path / "keep.py").write_text("pass\n")
    (tmp_path / ".gitignore").write_text("secret.py\n")
    found = discover_python_files(tmp_path)
    assert _names(found, tmp_path) == ["keep.py"]


def test_gitignore_negation_reincludes(tmp_path: Path) -> None:
    gen = tmp_path / "gen"
    gen.mkdir()
    (gen / "keep.py").write_text("pass\n")
    (gen / "drop.py").write_text("pass\n")
    (tmp_path / ".gitignore").write_text("gen/*\n!gen/keep.py\n")
    found = discover_python_files(tmp_path)
    assert _names(found, tmp_path) == ["gen/keep.py"]


def test_gitignore_anchored_pattern(tmp_path: Path) -> None:
    # An anchored pattern only matches at the root, not at depth.
    (tmp_path / "build.py").write_text("pass\n")
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "build.py").write_text("pass\n")
    (tmp_path / ".gitignore").write_text("/build.py\n")
    found = discover_python_files(tmp_path)
    assert _names(found, tmp_path) == ["pkg/build.py"]
