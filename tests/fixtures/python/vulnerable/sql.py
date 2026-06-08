# SPDX-License-Identifier: Apache-2.0
# Intentionally vulnerable fixture for detector `python.injection.sql`.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports a CWE-89 finding (input() -> string-built SQL ->
# cursor.execute, no bound parameters).
def query(cursor):
    name = input("name: ")                                      # taint source
    sql = "SELECT * FROM users WHERE name = '" + name + "'"      # tainted query
    cursor.execute(sql)                                         # dangerous sink
