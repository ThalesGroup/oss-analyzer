# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""Unit tests of security/scripts/policy.py (merge and resolution)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import policy  # noqa: E402


def base_policy() -> dict:
    return {
        "meta": {"distribution_model": "saas"},
        "vulnerabilities": {"fail_on": "high", "exceptions": [{"id": "CVE-1"}]},
        "licenses": {
            "allow": ["MIT", "Apache-2.0"],
            "review": ["MPL-2.0"],
            "deny": ["AGPL-3.0"],
            "by_distribution_model": {"distributed": {"deny": ["GPL-3.0"]}},
        },
    }


class MergeTest(unittest.TestCase):
    def test_project_setting_wins_over_base(self):
        merged = policy.merge_policies(base_policy(), {"vulnerabilities": {"fail_on": "critical"}})
        self.assertEqual(merged["vulnerabilities"]["fail_on"], "critical")

    def test_exceptions_add_up(self):
        merged = policy.merge_policies(
            base_policy(), {"vulnerabilities": {"exceptions": [{"id": "CVE-2"}]}})
        self.assertEqual([e["id"] for e in merged["vulnerabilities"]["exceptions"]],
                         ["CVE-1", "CVE-2"])

    def test_reclassified_license_leaves_its_old_list(self):
        merged = policy.merge_policies(base_policy(), {"licenses": {"allow": ["AGPL-3.0"]}})
        lic = merged["licenses"]
        self.assertIn("AGPL-3.0", lic["allow"])
        self.assertNotIn("AGPL-3.0", lic["deny"])
        self.assertEqual(lic["review"], ["MPL-2.0"])

    def test_license_ids_are_normalized_before_comparing(self):
        # Same normalization as license_gate.py (case, aliases, -only): without
        # it, both labels would stay in two lists at once.
        for project, base_list, base_id in (({"deny": ["mit"]}, "allow", "MIT"),
                                            ({"deny": ["Apache License 2.0"]}, "allow", "Apache-2.0"),
                                            ({"allow": ["AGPL-3.0-only"]}, "deny", "AGPL-3.0")):
            with self.subTest(project=project):
                merged = policy.merge_policies(base_policy(), {"licenses": project})
                self.assertNotIn(base_id, merged["licenses"][base_list])
                [(new_list, [label])] = project.items()
                self.assertIn(label, merged["licenses"][new_list])

    def test_inherit_false_ignores_the_base(self):
        project = {"meta": {"inherit": False}, "vulnerabilities": {"fail_on": "low"}}
        self.assertEqual(policy.merge_policies(base_policy(), project), project)

    def test_merge_does_not_mutate_its_inputs(self):
        base = base_policy()
        policy.merge_policies(base, {"licenses": {"allow": ["AGPL-3.0"]}})
        self.assertEqual(base, base_policy())

    def test_empty_section_in_project_keeps_the_base(self):
        # `licenses:` left empty in a project's policy-global.yml parses to None.
        merged = policy.merge_policies(base_policy(), {"licenses": None, "meta": None})
        self.assertEqual(merged["licenses"]["deny"], ["AGPL-3.0"])
        self.assertEqual(merged["meta"]["distribution_model"], "saas")


class ResolveTest(unittest.TestCase):
    def test_default_mode_is_enforce_for_every_category(self):
        resolved = policy.resolve_policy(base_policy())
        for category in policy.MODE_CATEGORIES:
            self.assertEqual(resolved[category]["mode"], "enforce")

    def test_global_mode_applies_but_a_category_mode_wins(self):
        pol = base_policy()
        pol["secrets"] = {"mode": "enforce"}
        resolved = policy.resolve_policy(pol, mode="audit")
        self.assertEqual(resolved["vulnerabilities"]["mode"], "audit")
        self.assertEqual(resolved["secrets"]["mode"], "enforce")

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            policy.resolve_policy(base_policy(), mode="strict")
        pol = base_policy()
        pol["sast"] = {"mode": "strict"}
        with self.assertRaises(ValueError):
            policy.resolve_policy(pol)

    def test_unknown_distribution_model_is_rejected(self):
        with self.assertRaises(ValueError):
            policy.resolve_policy(base_policy(), distribution_model="onprem")

    def test_distribution_model_reclassifies_licenses(self):
        resolved = policy.resolve_policy(base_policy(), distribution_model="distributed")
        self.assertIn("GPL-3.0", resolved["licenses"]["deny"])
        self.assertNotIn("by_distribution_model", resolved["licenses"])
        self.assertEqual(resolved["meta"]["distribution_model"], "distributed")

    def test_resolving_twice_changes_nothing(self):
        once = policy.resolve_policy(base_policy(), distribution_model="distributed", mode="audit")
        self.assertEqual(policy.resolve_policy(once), once)

    def test_empty_sections_do_not_crash(self):
        resolved = policy.resolve_policy({"meta": None, "licenses": None, "sast": None})
        self.assertEqual(resolved["licenses"]["mode"], "enforce")
        self.assertEqual(resolved["sast"]["mode"], "enforce")

    def test_base_model_rule_beats_a_project_common_list_but_not_its_model_rule(self):
        # Precedence (policy.py): model rules are applied after the merge, so
        # the project must use its own by_distribution_model. The organization
        # base has no model rule, but a base that adds one gets this behavior.
        base = base_policy()
        base["licenses"]["by_distribution_model"] = {"saas": {"allow": ["MPL-2.0"]}}

        def verdict(project: dict) -> list:
            lists = policy.resolve_policy(policy.merge_policies(base, project))["licenses"]
            return [v for v in policy.LICENSE_VERDICTS if "MPL-2.0" in lists[v]]

        self.assertEqual(verdict({}), ["allow"])
        self.assertEqual(verdict({"licenses": {"deny": ["MPL-2.0"]}}), ["allow"])
        self.assertEqual(
            verdict({"licenses": {"by_distribution_model": {"saas": {"deny": ["MPL-2.0"]}}}}),
            ["deny"])


class CheckPolicyTest(unittest.TestCase):
    def test_the_organization_base_is_clean(self):
        base = policy.load_policy(Path(__file__).resolve().parents[1] / "policy-global.yml")
        self.assertEqual(policy.check_policy(base), [])

    def test_unknown_keys_are_reported_not_fatal(self):
        warnings = policy.check_policy({"licenses": {"fail_on_reviews": True}, "sats": {}})
        self.assertEqual(sorted(warnings), ["licenses.fail_on_reviews: unknown key — ignored",
                                            "unknown section 'sats' — ignored"])

    def test_values_the_scripts_would_misread_are_errors(self):
        for bad, message in (
                ({"meta": {"version": 2}}, "settings format 2"),
                ({"vulnerabilities": {"fail_on": "hgih"}}, "vulnerabilities.fail_on"),
                ({"sast": {"fail_on": "severe"}}, "sast.fail_on"),
                ({"licenses": {"unknown": "maybe"}}, "licenses.unknown"),
                ({"licenses": {"fail_on_review": "yes"}}, "licenses.fail_on_review"),
                ({"vulnerabilities": {"exceptions": {"id": "CVE-1"}}}, "expected a list"),
                ({"secrets": ["fail_on_any"]}, "expected a mapping")):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, message):
                policy.resolve_policy(bad)


class ListsFileTest(unittest.TestCase):
    def write(self, name: str, text: str) -> Path:
        path = Path(self.dir.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def setUp(self):
        import tempfile
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.write("lists.yml", "allow: [MIT, MPL-2.0]\nreview: [GPL-3.0-only]\ndeny: [CC-BY-NC-4.0]\n")

    def test_lists_file_is_pulled_in_relative_to_the_policy(self):
        loaded = policy.load_policy(self.write("policy-global.yml", "licenses:\n  lists_file: lists.yml\n"))
        self.assertEqual(loaded["licenses"]["allow"], ["MIT", "MPL-2.0"])
        self.assertNotIn("lists_file", loaded["licenses"])

    def test_inline_lists_reclassify_the_lists_file(self):
        loaded = policy.load_policy(self.write(
            "policy-global.yml", "licenses:\n  lists_file: lists.yml\n  deny: [GPL-3.0-only]\n"))
        self.assertEqual(loaded["licenses"]["review"], [])
        self.assertEqual(loaded["licenses"]["deny"], ["CC-BY-NC-4.0", "GPL-3.0-only"])

    def test_policy_licenses_next_to_the_policy_is_pulled_in_without_lists_file(self):
        (Path(self.dir.name) / "policy-licenses.yml").write_text("deny: [GPL-3.0-only]\n",
                                                                 encoding="utf-8")
        loaded = policy.load_policy(self.write("policy-global.yml", "licenses:\n  unknown: deny\n"))
        self.assertEqual(loaded["licenses"]["deny"], ["GPL-3.0-only"])
        self.assertEqual(loaded["licenses"]["unknown"], "deny")

    def test_settings_folder_with_lists_only(self):
        (Path(self.dir.name) / "policy-licenses.yml").write_text("allow: [MIT]\n", encoding="utf-8")
        self.assertEqual(policy.load_settings_policy(Path(self.dir.name))["licenses"]["allow"], ["MIT"])
        self.assertEqual(policy.load_settings_policy(Path(self.dir.name) / "absent"), {})

    def test_missing_lists_file_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "not found"):
            policy.load_policy(self.write("policy-global.yml", "licenses:\n  lists_file: missing.yml\n"))


if __name__ == "__main__":
    unittest.main()
