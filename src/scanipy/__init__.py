# SPDX-License-Identifier: Apache-2.0
"""scanipy — local, private, taint-tracking SAST for your code (open-source edition).

scanipy follows untrusted data from *sources* to dangerous *sinks* through your
code and reports the data-flow trace behind every finding. Detection logic lives
in declarative taint-DSL specs (see :mod:`scanipy.dsl`), not in engine code.
"""

__version__ = "0.1.0"
