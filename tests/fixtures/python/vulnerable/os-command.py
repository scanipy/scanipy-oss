# SPDX-License-Identifier: Apache-2.0
# Intentionally vulnerable fixture for detector `python.injection.os-command`.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports a CWE-78 finding (input() -> os.system, no sanitizer).
import os


def main() -> None:
    name = input("name: ")          # taint source
    os.system("echo " + name)       # dangerous sink: OS command injection
