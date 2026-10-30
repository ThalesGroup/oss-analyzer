# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""
Layout of a license lists file (security/policy-licenses.yml): under each
verdict, entries sorted into groups, each group introduced by a comment
line naming it. build_license_catalog.py reads the groups back to tell the
non-SPDX entries written on purpose from mistakes. Standard library only.
"""
from __future__ import annotations

import json
import re

# Written as comments above each group of entries, and read back from them
# (read_groups): renaming one changes what an existing file reads as.
GROUPS = (
    "SPDX identifiers",
    "SPDX expressions with an exception",
    "ScanCode keys of licenses with no SPDX identifier",
    "Names of licenses with no SPDX identifier, as SBOMs may carry them",
    "IDs that are neither SPDX nor resolvable to an SPDX expression",
)
NAMES_GROUP = 3


def read_groups(text: str) -> dict[str, int]:
    """Reads back a lists file laid out in GROUPS: entry label → index in
    GROUPS, from the group comment above it. An entry under no known group
    comment (a file edited without them) is left out."""
    out: dict[str, int] = {}
    group = None
    for line in text.splitlines():
        m = re.fullmatch(r"  # (.+)", line)
        if m:
            group = GROUPS.index(m.group(1)) if m.group(1) in GROUPS else None
            continue
        m = re.match(r'  - ("(?:[^"\\]|\\.)*")', line)
        if m and group is not None:
            out[json.loads(m.group(1))] = group
        elif not line.startswith("  "):
            group = None   # a new verdict, or anything else at top level
    return out
