# SPDX-License-Identifier: Apache-2.0
# Intentionally vulnerable fixture for detector `python.xxe.xxe`.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports a CWE-611 finding (request data -> lxml.etree
# parser that resolves external entities).
import lxml.etree

import flask


def parse() -> object:
    payload = flask.request.data            # taint source
    return lxml.etree.fromstring(payload)   # dangerous sink: external entities
