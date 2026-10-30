# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""Unit tests of security/scripts/build_license_catalog.py (offline, synthetic sources)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import build_license_catalog as catalog  # noqa: E402

SPDX = [
    {"licenseId": "MIT", "isDeprecatedLicenseId": False},
    {"licenseId": "JSON", "isDeprecatedLicenseId": False},
    {"licenseId": "GPL-3.0-only", "isDeprecatedLicenseId": False},
    {"licenseId": "GPL-3.0", "isDeprecatedLicenseId": True},
    {"licenseId": "MPL-2.0", "isDeprecatedLicenseId": False},
    {"licenseId": "Bugroff", "isDeprecatedLicenseId": False},
    {"licenseId": "Apache-2.0", "isDeprecatedLicenseId": False},
]
EXCEPTIONS = [{"licenseExceptionId": "LLVM-exception"}]
SCANCODE = [
    {"license_key": "mit", "category": "Permissive", "spdx_license_key": "MIT"},
    {"license_key": "json", "category": "Permissive", "spdx_license_key": "JSON"},
    {"license_key": "gpl-3.0", "category": "Copyleft", "spdx_license_key": "GPL-3.0-only",
     "other_spdx_license_keys": ["GPL-3.0"]},
    {"license_key": "mpl-2.0", "category": "Copyleft Limited", "spdx_license_key": "MPL-2.0"},
    {"license_key": "apache-2.0", "category": "Permissive", "spdx_license_key": "Apache-2.0"},
    {"license_key": "commons-clause", "category": "Source-available",
     "spdx_license_key": "LicenseRef-scancode-commons-clause"},
    {"license_key": "proprietary", "category": "Commercial", "spdx_license_key": None,
     "is_deprecated": True},
    {"license_key": "proprietary-license", "category": "Commercial",
     "spdx_license_key": "LicenseRef-scancode-proprietary-license"},
]
POLICY = {
    "unknown": "review",
    "allow": ["MIT", "Apache-2.0 WITH LLVM-exception"],
    "deny": ["JSON", "GPL-3.0", "Commons-Clause", "LicenseRef-scancode-proprietary"],
}


def build() -> dict:
    return catalog.build_catalog(SPDX, EXCEPTIONS, SCANCODE, POLICY)


def verdicts(result: dict) -> dict:
    return {e["id"]: (e["verdict"], e["source"]) for e in result["entries"]}


class CatalogTest(unittest.TestCase):
    def test_policy_wins_then_scancode_then_unknown(self):
        v = verdicts(build())
        self.assertEqual(v["JSON"], ("deny", "policy"))
        self.assertEqual(v["MPL-2.0"], ("review", "scancode"))
        self.assertEqual(v["Bugroff"], ("review", "unclassified"))

    def test_policy_labels_are_normalized(self):
        # `GPL-3.0` in the policy decides `GPL-3.0-only` too, as in the gate.
        self.assertEqual(verdicts(build())["GPL-3.0-only"], ("deny", "policy"))

    def test_disagreement_with_scancode_is_reported(self):
        self.assertEqual([(d["id"], d["policy"], d["scancode"]) for d in build()["disagreements"]],
                         [("JSON", "deny", "allow")])

    def test_spdx_with_expression_is_kept(self):
        self.assertEqual([e["id"] for e in build()["with_entries"]],
                         ["Apache-2.0 WITH LLVM-exception"])

    def test_lowercase_with_is_still_an_spdx_expression(self):
        result = catalog.build_catalog(SPDX, EXCEPTIONS, SCANCODE,
                                       {"allow": ["Apache-2.0 with LLVM-exception"]})
        self.assertEqual([e["id"] for e in result["with_entries"]], ["Apache-2.0 with LLVM-exception"])
        self.assertEqual(result["not_spdx"], [])

    def test_unreadable_or_wrong_source_is_a_clean_error(self):
        import io
        import tempfile
        from contextlib import redirect_stderr
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            wrong = Path(d) / "exceptions.json"   # given where licenses.json is expected
            wrong.write_text('{"exceptions": []}', encoding="utf-8")
            policy = Path(d) / "policy-global.yml"
            policy.write_text("licenses: {}\n", encoding="utf-8")
            argv = ["build_license_catalog.py", "--policy", str(policy),
                    "--spdx-licenses", str(wrong), "--spdx-exceptions", str(wrong),
                    "--scancode", str(wrong), "--output-dir", str(Path(d) / "out")]
            err = io.StringIO()
            with mock.patch.object(sys, "argv", argv), redirect_stderr(err):
                self.assertEqual(catalog.main(), 2)
            self.assertIn("::error::", err.getvalue())

    def test_non_spdx_entries_get_the_live_scancode_key(self):
        suggestions = {e["id"]: e["suggestion"] for e in build()["not_spdx"]}
        self.assertEqual(suggestions, {
            "Commons-Clause": "LicenseRef-scancode-commons-clause",
            "LicenseRef-scancode-proprietary": "LicenseRef-scancode-proprietary-license",
        })

    def test_entries_written_on_purpose_are_only_counted(self):
        # A live ScanCode key and a listed name are expected; a stale key, an
        # unknown LicenseRef and a name the lists file doesn't hold are reported.
        policy = {"allow": ["LicenseRef-scancode-commons-clause", "Commons Clause License",
                            "LicenseRef-scancode-proprietary", "LicenseRef-custom", "Comons-Clause"]}
        result = catalog.build_catalog(SPDX, EXCEPTIONS, SCANCODE, policy,
                                       frozenset({catalog.license_key("Commons Clause License")}))
        self.assertEqual({e["id"]: e["reason"] for e in result["not_spdx_expected"]}, {
            "LicenseRef-scancode-commons-clause": "scancode-key",
            "Commons Clause License": "listed-name",
        })
        self.assertEqual(sorted(e["id"] for e in result["not_spdx"]),
                         ["Comons-Clause", "LicenseRef-custom", "LicenseRef-scancode-proprietary"])
        md = catalog.render_markdown(result, {"spdx": "x", "scancode": "y"}, catalog.Counter())
        self.assertIn("1 LicenseRef keys of live ScanCode licenses, 1 listed names", md)

    def test_section_says_so_when_nothing_looks_like_a_mistake(self):
        result = catalog.build_catalog(SPDX, EXCEPTIONS, SCANCODE,
                                       {"allow": ["LicenseRef-scancode-commons-clause"]})
        md = catalog.render_markdown(result, {"spdx": "x", "scancode": "y"}, catalog.Counter())
        self.assertIn("None that looks like a mistake.", md)
        self.assertNotIn("| Entry |", md)

    def test_listed_names_come_from_the_lists_file_names_group(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "policy-global.yml").write_text(
                "licenses:\n  lists_file: lists.yml\n", encoding="utf-8")
            (Path(d) / "lists.yml").write_text(
                'allow:\n'
                '  # ScanCode keys of licenses with no SPDX identifier\n'
                '  - "LicenseRef-scancode-commons-clause"  # a comment\n'
                '  # Names of licenses with no SPDX identifier, as SBOMs may carry them\n'
                '  - "Commons Clause License"  # a comment\n'
                'deny:\n'
                '  - "Not In A Group"\n', encoding="utf-8")
            names = catalog.listed_names(Path(d) / "policy-global.yml")
        self.assertEqual(names, frozenset({catalog.license_key("Commons Clause License")}))

    def test_only_deprecated_ids_written_in_the_policy_are_flagged(self):
        self.assertEqual(build()["deprecated_in_policy"], ["GPL-3.0"])

    def test_yaml_draft_holds_every_entry(self):
        import yaml
        result = build()
        lists = yaml.safe_load(catalog.render_yaml(result, {"spdx": "x", "scancode": "y"}))["licenses"]
        self.assertEqual(sum(len(v) for v in lists.values()),
                         len(result["entries"]) + len(result["with_entries"])
                         + len(result["not_spdx"]) + len(result["not_spdx_expected"]))
        self.assertIn("Apache-2.0 WITH LLVM-exception", lists["allow"])


if __name__ == "__main__":
    unittest.main()
