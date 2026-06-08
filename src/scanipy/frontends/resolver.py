# SPDX-License-Identifier: Apache-2.0
"""Import / alias resolution — canonicalize names to dotted paths.

This is the load-bearing step that lets dotted DSL patterns match aliased
imports. Without it ``from os import system; system(x)``,
``import os as o; o.system(x)``, and ``import os.path as p; p.join(x)`` would all
silently fail to match the patterns ``os.system`` / ``os.path.join`` (false
negatives).

Two public functions:

* :func:`build_import_table` scans a sequence of ``ast`` statements (a module or
  function body) and returns the :class:`~scanipy.ir.ImportTable` of bindings it
  introduces, in source order.
* :func:`canonical_dotted` maps an ``ast.Name``/``ast.Attribute`` chain to its
  canonical dotted path, rewriting the imported root via the table and leaving
  ordinary local variables bare (so value-rooted chains like
  ``conn.cursor.execute`` are preserved for ``*.execute`` patterns).

``ast`` lives here and in :mod:`scanipy.frontends.python_frontend` only; the IR,
matcher, and engine never import ``ast``.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from scanipy.ir import ImportEntry, ImportTable
from scanipy.models import Location

# Marker prefix for relative imports (``from . import x`` / ``from .pkg import y``).
# Intra-file resolution cannot know the absolute package, so we record the dots
# verbatim and never claim a misleading canonical path (P7).
_RELATIVE = "."
# Marker suffix recorded for a star import (``from m import *``); the bound names
# are unknown, so this entry never resolves a concrete reference.
_STAR = "*"


def _loc_of(node: ast.AST, *, file: str = "<unknown>") -> Location:
    """Build a :class:`Location` from an ``ast`` node (1-based line, 0-based col)."""
    line = getattr(node, "lineno", 1)
    column = getattr(node, "col_offset", 0)
    end_line = getattr(node, "end_lineno", None)
    end_column = getattr(node, "end_col_offset", None)
    return Location(
        file=file,
        line=line,
        column=column,
        end_line=end_line,
        end_column=end_column,
    )


def build_import_table(
    nodes: Iterable[ast.stmt],
    *,
    file: str = "<unknown>",
) -> ImportTable:
    """Return the :class:`ImportTable` of bindings introduced by ``nodes``.

    Handles every binding import form:

    * ``import os`` -> local ``os`` -> canonical ``os`` (kind ``module``).
    * ``import os.path`` -> local ``os`` -> canonical ``os`` (the bound name is the
      top package); the dotted access ``os.path`` is canonicalized by
      :func:`canonical_dotted` walking the attribute chain.
    * ``import os.path as p`` -> local ``p`` -> canonical ``os.path``.
    * ``import os as o`` -> local ``o`` -> canonical ``os``.
    * ``from os import system`` -> local ``system`` -> canonical ``os.system``
      (kind ``name``).
    * ``from os import system as s`` -> local ``s`` -> canonical ``os.system``.
    * ``from . import x`` / relative imports are recorded with a leading-dot
      canonical marker (never claimed as resolvable).
    * ``from m import *`` is recorded as a star marker and never resolves names.

    Only top-level statements of ``nodes`` are inspected; nested scopes build
    their own tables.
    """
    entries: list[ImportEntry] = []
    for node in nodes:
        if isinstance(node, ast.Import):
            entries.extend(_entries_from_import(node, file=file))
        elif isinstance(node, ast.ImportFrom):
            entries.extend(_entries_from_import_from(node, file=file))
    return ImportTable(entries=tuple(entries))


def _entries_from_import(node: ast.Import, *, file: str) -> list[ImportEntry]:
    """Lower an ``import a, b.c as d`` statement to import entries."""
    out: list[ImportEntry] = []
    loc = _loc_of(node, file=file)
    for alias in node.names:
        if alias.asname is not None:
            # `import a.b.c as d` -> local `d` resolves to the full `a.b.c`.
            out.append(
                ImportEntry(
                    local_name=alias.asname,
                    canonical=alias.name,
                    kind="module",
                    asname=alias.asname,
                    location=loc,
                )
            )
        else:
            # `import a.b.c` binds the top package `a`; the access `a.b.c` is
            # canonicalized by walking the attribute chain.
            top = alias.name.split(".", 1)[0]
            out.append(
                ImportEntry(
                    local_name=top,
                    canonical=top,
                    kind="module",
                    asname=None,
                    location=loc,
                )
            )
    return out


def _entries_from_import_from(node: ast.ImportFrom, *, file: str) -> list[ImportEntry]:
    """Lower a ``from m import n as a`` statement to import entries."""
    out: list[ImportEntry] = []
    loc = _loc_of(node, file=file)
    # Relative imports carry a non-zero level (number of leading dots).
    prefix = _RELATIVE * node.level
    module = node.module or ""
    base = f"{prefix}{module}" if prefix else module
    for alias in node.names:
        if alias.name == _STAR:
            # `from m import *` — bound names are unknown; record a marker.
            out.append(
                ImportEntry(
                    local_name=_STAR,
                    canonical=f"{base}.{_STAR}" if base else _STAR,
                    kind="star",
                    asname=None,
                    location=loc,
                )
            )
            continue
        local = alias.asname or alias.name
        if prefix:
            # Relative import: record without a misleading absolute canonical.
            canonical = f"{base}.{alias.name}" if base != prefix else f"{prefix}{alias.name}"
        else:
            canonical = f"{base}.{alias.name}" if base else alias.name
        out.append(
            ImportEntry(
                local_name=local,
                canonical=canonical,
                kind="name",
                asname=alias.asname,
                location=loc,
            )
        )
    return out


def canonical_dotted(expr: ast.expr, table: ImportTable) -> str | None:
    """Map a name/attribute chain to its canonical dotted path, or ``None``.

    * ``ast.Name`` -> the import-resolved canonical when the name is imported,
      else the bare name (an ordinary local).
    * ``ast.Attribute`` -> the dotted chain with its *root* canonicalized via the
      table; e.g. ``import os.path as p; p.join`` -> ``"os.path.join"``,
      ``conn.cursor.execute`` -> ``"conn.cursor.execute"`` (local root kept bare).
    * Any other root (a call, subscript, literal, ...) -> ``None`` (the chain is
      not name-rooted and cannot be canonicalized to a dotted path).

    Returns ``None`` for unresolvable relative/star roots rather than emitting a
    misleading path.
    """
    segments = _dotted_segments(expr)
    if segments is None:
        return None
    root, *rest = segments
    entry = table.resolve(root)
    if entry is None:
        # Ordinary local (variable or unimported name): keep the chain bare.
        return ".".join(segments)
    if entry.kind == "star":
        # Star imports bind unknown names; do not claim resolution.
        return None
    if entry.canonical.startswith(_RELATIVE):
        # Relative import root: unresolvable to an absolute dotted path (P7).
        return None
    return ".".join([entry.canonical, *rest])


def _dotted_segments(expr: ast.expr) -> list[str] | None:
    """Flatten a name/attribute chain to its segments, root-first, or ``None``.

    ``a.b.c`` -> ``["a", "b", "c"]``; ``a`` -> ``["a"]``; a non-name-rooted chain
    (e.g. ``f().b``) -> ``None``.
    """
    parts: list[str] = []
    cur: ast.expr = expr
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return parts
    return None
