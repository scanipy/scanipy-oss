# SPDX-License-Identifier: Apache-2.0
"""File discovery — find the Python files to analyze.

:func:`discover_python_files` walks a path for ``*.py`` files in a deterministic,
sorted order (P3), skipping noise directories (``.venv``, ``.git``,
``__pycache__``, build artifacts, …) by default and honoring caller-supplied
``--exclude`` globs and (by default) the project's ``.gitignore``.

Everything here is stdlib-only (P6 — minimal dependencies). ``.gitignore`` support
is a **bounded subset** of git's pattern language, not a full reimplementation:

* blank lines and ``#`` comments are ignored;
* a leading ``!`` negates a pattern (un-ignores);
* a leading ``/`` anchors a pattern to the gitignore's directory;
* a trailing ``/`` matches directories only;
* ``*``/``?``/``[...]`` are shell-style (via :func:`fnmatch`), and ``**`` matches
  across directory separators;
* a pattern with no slash matches by basename at any depth.

Git semantics this subset does **not** reproduce (honest scope, P7): per-directory
nested ``.gitignore`` precedence subtleties, ``\\`` escapes, and the full ordering
rules. Only the repository-root (scan-root) ``.gitignore`` is read.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

# Directory names skipped unconditionally — analysis noise, never user code.
DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        ".env",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "build",
        "dist",
        ".eggs",
        "node_modules",
        ".idea",
        ".vscode",
    }
)

_GITIGNORE_FILENAME = ".gitignore"


def discover_python_files(
    path: str | Path,
    *,
    exclude: Sequence[str] = (),
    use_gitignore: bool = True,
) -> tuple[Path, ...]:
    """Return the ``*.py`` files under ``path`` to analyze, sorted (P3).

    ``path`` may be a single file (returned as-is when it is a ``*.py`` file) or a
    directory (walked recursively). ``exclude`` is a sequence of globs matched
    against each candidate's path (relative to the scan root, and by basename);
    when ``use_gitignore`` is true the scan-root ``.gitignore`` is honored too.
    """
    root = Path(path)
    if root.is_file():
        if root.suffix == ".py":
            return (root,)
        return ()

    rules = _load_gitignore(root) if use_gitignore else ()
    results: list[Path] = []
    _walk(root, root, exclude, rules, results)
    return tuple(sorted(results))


def _walk(
    current: Path,
    root: Path,
    exclude: Sequence[str],
    rules: Sequence[_GitignoreRule],
    out: list[Path],
) -> None:
    try:
        entries = sorted(current.iterdir(), key=lambda p: p.name)
    except OSError:
        return
    for entry in entries:
        rel = entry.relative_to(root)
        if entry.is_dir():
            if entry.name in DEFAULT_EXCLUDE_DIRS:
                continue
            if _excluded_by_globs(rel, exclude):
                continue
            if _ignored(rel, is_dir=True, rules=rules):
                continue
            _walk(entry, root, exclude, rules, out)
        elif entry.is_file():
            if entry.suffix != ".py":
                continue
            if _excluded_by_globs(rel, exclude):
                continue
            if _ignored(rel, is_dir=False, rules=rules):
                continue
            out.append(entry)


def _excluded_by_globs(rel: Path, globs: Sequence[str]) -> bool:
    """True if ``rel`` matches any ``--exclude`` glob.

    Each glob is matched against the POSIX relative path and against the basename,
    so both ``--exclude 'tests/*'`` and ``--exclude '*.gen.py'`` work.
    """
    if not globs:
        return False
    rel_posix = rel.as_posix()
    name = rel.name
    for glob in globs:
        if fnmatch.fnmatch(rel_posix, glob) or fnmatch.fnmatch(name, glob):
            return True
    return False


# ---------------------------------------------------------------------------
# .gitignore (bounded subset)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _GitignoreRule:
    """One compiled gitignore line."""

    pattern: str  # normalized, without leading '!' or '/' or trailing '/'
    negated: bool
    anchored: bool
    dir_only: bool


def _load_gitignore(root: Path) -> tuple[_GitignoreRule, ...]:
    gitignore = root / _GITIGNORE_FILENAME
    if not gitignore.is_file():
        return ()
    try:
        text = gitignore.read_text(encoding="utf-8")
    except OSError:
        return ()
    return _parse_gitignore(text)


def _parse_gitignore(text: str) -> tuple[_GitignoreRule, ...]:
    rules: list[_GitignoreRule] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        negated = line.startswith("!")
        if negated:
            line = line[1:]
        dir_only = line.endswith("/")
        if dir_only:
            line = line[:-1]
        anchored = line.startswith("/")
        if anchored:
            line = line[1:]
        if not line:
            continue
        rules.append(
            _GitignoreRule(pattern=line, negated=negated, anchored=anchored, dir_only=dir_only)
        )
    return tuple(rules)


def _ignored(rel: Path, *, is_dir: bool, rules: Sequence[_GitignoreRule]) -> bool:
    """Apply gitignore ``rules`` to a path relative to the scan root.

    Later rules win (git semantics), so a trailing ``!`` negation can re-include a
    previously-ignored path.
    """
    if not rules:
        return False
    rel_posix = rel.as_posix()
    decision = False
    for rule in rules:
        if rule.dir_only and not is_dir:
            continue
        if _rule_matches(rule, rel_posix):
            decision = not rule.negated
    return decision


def _rule_matches(rule: _GitignoreRule, rel_posix: str) -> bool:
    pattern = rule.pattern
    if rule.anchored or "/" in pattern:
        return _match_path(pattern, rel_posix)
    # Unanchored, slash-free pattern: match the basename at any depth.
    basename = PurePosixPath(rel_posix).name
    return fnmatch.fnmatch(basename, pattern)


def _match_path(pattern: str, rel_posix: str) -> bool:
    """Match a slash-bearing/anchored gitignore pattern against a relative path.

    Matches the path itself and any descendant (so ``build`` ignores
    ``build/x.py``). ``**`` is expanded to cross directory separators.
    """
    candidates = (rel_posix, *_ancestors(rel_posix))
    for candidate in candidates:
        if _fnmatch_with_globstar(candidate, pattern):
            return True
    return False


def _ancestors(rel_posix: str) -> Iterable[str]:
    parts = rel_posix.split("/")
    for i in range(1, len(parts)):
        yield "/".join(parts[:i])


def _fnmatch_with_globstar(name: str, pattern: str) -> bool:
    if "**" not in pattern:
        return fnmatch.fnmatch(name, pattern)
    # Translate ** to match across separators by trying both "any path" and
    # "nothing" expansions via a simple regex-free fallback: replace ** with *
    # but allow it to span '/'. fnmatch's '*' does not cross '/', so we compare
    # segment counts loosely by collapsing.
    regex_pattern = _globstar_to_fnmatch(pattern)
    return fnmatch.fnmatch(name, regex_pattern)


def _globstar_to_fnmatch(pattern: str) -> str:
    # Collapse '**/' and '/**' so a single '*' (which fnmatch treats as
    # not-crossing '/') is replaced by matching the flattened path. We flatten by
    # turning '**' into '*' and matching against the path with '/' kept; callers
    # also test ancestors, which covers the common 'dir/**' case.
    return pattern.replace("**/", "*").replace("/**", "*").replace("**", "*")
