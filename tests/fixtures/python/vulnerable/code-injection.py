# SPDX-License-Identifier: Apache-2.0
# Intentionally vulnerable fixture for detector `python.injection.code-injection`.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports a CWE-94 finding (input() -> eval, arbitrary code).
def run() -> None:
    expr = input("expr: ")      # taint source
    result = eval(expr)         # dangerous sink: arbitrary code execution
    print(result)
