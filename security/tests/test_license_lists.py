# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""Unit tests of security/scripts/license_lists.py (lists file layout)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import license_lists  # noqa: E402

LISTS = (
    'allow:\n'
    '  # SPDX identifiers\n'
    '  - "MIT"\n'
    '  # Names of licenses with no SPDX identifier, as SBOMs may carry them\n'
    '  - "Amazon Software License"\n'
    '  - "ASL \\"v1\\""  # a comment after the entry\n'
    'review:\n'
    '  - "Not In A Group"\n'
    '  # Not a known group\n'
    '  - "Under An Unknown Comment"\n'
    'deny:\n'
    '  # ScanCode keys of licenses with no SPDX identifier\n'
    '  - "LicenseRef-scancode-xyz"\n'
)


class ReadGroupsTest(unittest.TestCase):
    def test_entries_get_the_group_of_the_comment_above_them(self):
        self.assertEqual(license_lists.read_groups(LISTS), {
            "MIT": 0,
            "Amazon Software License": license_lists.NAMES_GROUP,
            'ASL "v1"': license_lists.NAMES_GROUP,
            "LicenseRef-scancode-xyz": 2,
        })

    def test_the_shipped_lists_file_only_uses_known_groups(self):
        lists = Path(__file__).resolve().parents[1] / "policy-licenses.yml"
        text = lists.read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.startswith("  # "):
                self.assertIn(line[4:], license_lists.GROUPS, line)
        self.assertTrue(license_lists.read_groups(text))


if __name__ == "__main__":
    unittest.main()
