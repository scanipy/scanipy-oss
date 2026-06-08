# SPDX-License-Identifier: Apache-2.0
"""Process exit codes used across the CLI.

Chosen so CI can branch on the result: a clean scan is ``0``, a scan that found
something at or above the configured threshold is ``1``, and anything else
(usage error, crash, or a not-yet-implemented stub) is ``2``.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Conventional ``scanipy`` exit codes."""

    OK = 0
    FINDINGS = 1
    ERROR = 2
