# SPDX-License-Identifier: Apache-2.0
# Interprocedural true-positive fixture (exercises TITO function summaries).
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports a CWE-78 finding. Taint flows from input() in the
# caller, through the call into run_cmd's parameter (a param -> sink summary
# flow), to os.system inside the callee; the witness is spliced across the call.
import os


def run_cmd(command: str) -> None:
    os.system(command)              # dangerous sink, reached via the parameter


def handler() -> None:
    name = input("name: ")          # taint source (caller side)
    run_cmd("echo " + name)         # taint enters run_cmd's parameter
