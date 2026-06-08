# SPDX-License-Identifier: Apache-2.0
# Interprocedural true-negative fixture (exercises TITO function summaries).
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports NO finding. The callee sanitizes its parameter with
# os.path.basename before the open() sink on the only path through it, so the
# param -> sink summary flow carries no live taint and nothing is flagged (P5).
import os


def read_file(name: str) -> str:
    safe = os.path.basename(name)   # sanitizes the parameter on the only path
    with open(safe) as handle:      # safe sink: name is directory-stripped
        return handle.read()


def handler() -> str:
    user = input("file: ")          # taint source (caller side)
    return read_file(user)          # taint enters read_file, but is sanitized
