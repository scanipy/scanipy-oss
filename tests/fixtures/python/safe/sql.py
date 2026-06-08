# SPDX-License-Identifier: Apache-2.0
# Intentionally SAFE counterpart to the sql injection fixture.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports NO finding. The untrusted value is passed as a bound
# parameter (arg index 1), while the sink checks only the query string (arg 0).
def query(cursor):
    name = input("name: ")                                          # taint source
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))   # safe: bound param
