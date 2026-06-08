# SPDX-License-Identifier: Apache-2.0
# Intentionally SAFE counterpart to the unsafe-deserialization fixture.
# This file is analysis DATA, not project code — it is excluded from ruff/mypy.
# Expected: scanipy reports NO finding. yaml.safe_load is a different, safe sink
# (it never constructs arbitrary objects), so the tainted value never reaches a
# flagged sink (yaml.load / pickle.load*).
import flask
import yaml


def load() -> object:
    blob = flask.request.data       # taint source
    return yaml.safe_load(blob)     # safe: SafeLoader, no arbitrary construction
