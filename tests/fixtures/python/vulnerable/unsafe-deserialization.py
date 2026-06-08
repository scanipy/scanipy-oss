# SPDX-License-Identifier: Apache-2.0
# Intentionally vulnerable fixture for detector
# `python.deserialization.unsafe-deserialization`.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports a CWE-502 finding (request data -> pickle.loads, which
# can execute arbitrary code while unpickling).
import pickle

import flask


def load() -> object:
    blob = flask.request.data       # taint source
    return pickle.loads(blob)       # dangerous sink: arbitrary code on unpickle
