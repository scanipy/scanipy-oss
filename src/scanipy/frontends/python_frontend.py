# SPDX-License-Identifier: Apache-2.0
"""Python frontend (0.1.0 scaffold).

Will build a normalized module from the standard-library :mod:`ast`, so the
Python frontend has no third-party parser dependency.
"""

from __future__ import annotations

from pathlib import Path

from scanipy.frontends.base import Frontend


class PythonFrontend(Frontend):
    """Parses Python source via the standard-library AST."""

    language = "python"

    def parse(self, path: Path) -> object:
        raise NotImplementedError(
            "the Python frontend is not implemented in the 0.1.0 scaffold; "
            "see the taint-engine agent."
        )
