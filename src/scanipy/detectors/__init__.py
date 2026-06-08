# SPDX-License-Identifier: Apache-2.0
"""Bundled detector specs (taint-DSL YAML).

The ``*.yml`` files in this package are the built-in detectors. They are
declarative data, not code (principle P4) — discovered by
:func:`scanipy.registry.discover_spec_files` and parsed by
:func:`scanipy.dsl.parse_spec`. See ``docs/dsl-reference.md`` for the schema.
"""
