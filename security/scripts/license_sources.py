# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""
Upstream license databases, shared by the license scripts
(build_license_catalog.py, and the converter generating the organization's
policy-licenses.yml). Standard library only: no PyYAML needed to fetch
them.
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

SPDX_LICENSES_URL = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json"
SPDX_EXCEPTIONS_URL = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/exceptions.json"
# GitHub mirror of scancode-licensedb.aboutcode.org/index.json (the site
# itself is unreachable from some networks).
SCANCODE_URL = "https://raw.githubusercontent.com/aboutcode-org/scancode-licensedb/main/docs/index.json"


def fetch_json(source: str) -> Any:
    """A URL, or a local file for offline runs."""
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=60) as resp:  # noqa: S310 (fixed URLs or user's choice)
            return json.load(resp)
    return json.loads(Path(source).read_text(encoding="utf-8"))
