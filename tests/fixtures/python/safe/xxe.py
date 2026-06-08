# SPDX-License-Identifier: Apache-2.0
# Intentionally SAFE counterpart to the XXE fixture.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports NO finding. defusedxml.ElementTree.fromstring is a
# different, safe sink (entity resolution disabled); the XXE sink patterns are
# module-qualified (lxml.etree.* / xml.etree.ElementTree.*) so they never match it.
import defusedxml.ElementTree

import flask


def parse() -> object:
    payload = flask.request.data                        # taint source
    return defusedxml.ElementTree.fromstring(payload)   # safe: entities disabled
