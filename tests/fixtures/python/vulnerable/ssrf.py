# SPDX-License-Identifier: Apache-2.0
# Intentionally vulnerable fixture for detector `python.ssrf.ssrf`.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports a CWE-918 finding (input() -> requests.get URL).
import requests


def fetch() -> bytes:
    url = input("url: ")            # taint source
    response = requests.get(url)    # dangerous sink: server-side request forgery
    return response.content
