# SPDX-License-Identifier: Apache-2.0
# Intentionally SAFE counterpart to the path-traversal fixture.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports NO finding. os.path.basename strips any directory
# component (a declared sanitizer), so the cleaned value reaches open() untainted.
import os


def read() -> str:
    name = os.path.basename(input("file: "))    # sanitized: directory stripped
    path = os.path.join("/srv/data", name)      # safe: name has no "../"
    with open(path) as handle:                  # safe sink
        return handle.read()
