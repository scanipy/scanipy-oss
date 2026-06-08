# SPDX-License-Identifier: Apache-2.0
# Intentionally vulnerable fixture for detector `python.traversal.path-traversal`.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports a CWE-22 finding (input() -> os.path.join -> open;
# the untrusted name can contain "../" and escape the base directory).
import os


def read() -> str:
    name = input("file: ")                  # taint source
    path = os.path.join("/srv/data", name)  # taint carried through join
    with open(path) as handle:              # dangerous sink: path traversal
        return handle.read()
