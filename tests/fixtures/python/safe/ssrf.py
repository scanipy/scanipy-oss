# SPDX-License-Identifier: Apache-2.0
# Intentionally SAFE counterpart to the SSRF fixture.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports NO finding. The URL is a constant the attacker cannot
# control, so no taint reaches the request. NOTE (P7): the real-world fix is an
# allow-list host check, which is application-specific and not expressible as a
# pattern-matched string sanitizer in v1 — see docs/dsl-reference.md. This TN
# therefore demonstrates the untainted-input case rather than a sanitizer.
import requests


def fetch() -> bytes:
    url = "https://api.example.com/status"  # constant, attacker cannot control
    response = requests.get(url)            # safe: untrusted data never reaches here
    return response.content
