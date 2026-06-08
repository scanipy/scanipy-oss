# SPDX-License-Identifier: Apache-2.0
"""Language frontends: parse source into the shared IR for the engine."""

from __future__ import annotations

from scanipy.frontends.base import Frontend
from scanipy.frontends.python_frontend import PythonFrontend
from scanipy.frontends.resolver import build_import_table, canonical_dotted
from scanipy.ir import (
    Expr,
    ImportEntry,
    ImportTable,
    IRAttribute,
    IRBlock,
    IRCall,
    IRFunction,
    IRKeyword,
    IRLiteral,
    IRModule,
    IRName,
    IRParam,
    Stmt,
    Target,
)

__all__ = [
    "Expr",
    "Frontend",
    "IRAttribute",
    "IRBlock",
    "IRCall",
    "IRFunction",
    "IRKeyword",
    "IRLiteral",
    "IRModule",
    "IRName",
    "IRParam",
    "ImportEntry",
    "ImportTable",
    "PythonFrontend",
    "Stmt",
    "Target",
    "build_import_table",
    "canonical_dotted",
]
