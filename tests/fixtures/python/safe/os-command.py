# SPDX-License-Identifier: Apache-2.0
# Intentionally SAFE counterpart to the os-command injection fixture.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports NO finding (no shell, and the input is quoted).
import shlex
import subprocess


def main() -> None:
    name = input("name: ")                              # taint source
    subprocess.run(["echo", shlex.quote(name)], check=True)  # safe: no shell, quoted
