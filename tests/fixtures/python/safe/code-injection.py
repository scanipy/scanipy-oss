# SPDX-License-Identifier: Apache-2.0
# Intentionally SAFE counterpart to the code-injection fixture.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports NO finding. ast.literal_eval is a different, safe sink
# (not eval/exec/compile), so the tainted value never reaches a flagged sink.
import ast


def run() -> None:
    expr = input("number: ")            # taint source
    result = ast.literal_eval(expr)     # safe: parses literals only, no code exec
    print(result)
