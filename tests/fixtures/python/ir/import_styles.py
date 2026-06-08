# SPDX-License-Identifier: Apache-2.0
# IR frontend test input (analysis DATA — excluded from ruff/mypy).
# Exercises the four import styles + value-rooted method chains.
import os
import os as o
import os.path as p
from os import system
from os import system as sys_call
from subprocess import run


def styles(conn, x):
    os.system(x)
    o.system(x)
    system(x)
    sys_call(x)
    run(x, shell=True)
    p.join(x)
    conn.cursor.execute(x)
