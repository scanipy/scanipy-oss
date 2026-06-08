# SPDX-License-Identifier: Apache-2.0
"""DOCS_TEST_1 — version + changelog consistency (H green).

Asserts the locked 0.2.0 facts:

* ``scanipy.__version__ == "0.2.0"`` (so ``scanipy version`` prints
  ``scanipy 0.2.0``), and
* ``CHANGELOG.md`` carries a dated ``## [0.2.0]`` section plus a fresh empty
  ``## [Unreleased]`` heading.

Hermetic: reads the repo's own files, no network/subprocess.
"""

from __future__ import annotations

import re
from pathlib import Path

import scanipy

REPO_ROOT = Path(__file__).resolve().parents[2]
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
EXPECTED_VERSION = "0.2.0"


def test_version_is_locked() -> None:
    assert scanipy.__version__ == EXPECTED_VERSION


def test_changelog_has_dated_0_2_0_section() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    # A dated 0.2.0 heading: "## [0.2.0] - YYYY-MM-DD".
    assert re.search(
        rf"^## \[{re.escape(EXPECTED_VERSION)}\] - \d{{4}}-\d{{2}}-\d{{2}}$",
        text,
        flags=re.MULTILINE,
    ), "CHANGELOG.md is missing a dated `## [0.2.0] - YYYY-MM-DD` section"


def test_changelog_keeps_a_fresh_unreleased_section() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    assert re.search(r"^## \[Unreleased\]$", text, flags=re.MULTILINE), (
        "CHANGELOG.md should keep a fresh `## [Unreleased]` heading"
    )


def test_changelog_version_ref_resolves() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    assert re.search(rf"^\[{re.escape(EXPECTED_VERSION)}\]: https://", text, flags=re.MULTILINE), (
        "CHANGELOG.md is missing the [0.2.0] link reference"
    )
