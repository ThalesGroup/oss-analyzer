# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""Unit tests of security/scripts/prepare_settings.py, against the real
organization defaults (security/) and a temporary project settings folder."""
import io
import sys
import tempfile
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import yaml

SECURITY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SECURITY / "scripts"))

import prepare_settings as prep  # noqa: E402


class PrepareTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = Path(self.tmp.name) / "security"
        self.settings.mkdir()
        self.out = Path(self.tmp.name) / "out"

    def write(self, name: str, text: str) -> None:
        (self.settings / name).write_text(text, encoding="utf-8")

    def run_main(self, settings: Path | None = None) -> tuple[int, str, str]:
        argv = ["prepare_settings.py", "--defaults", str(SECURITY),
                "--settings-dir", str(settings or self.settings),
                "--output-dir", str(self.out), "--mode", "enforce"]
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", argv), redirect_stdout(out), redirect_stderr(err):
            rc = prep.main()
        return rc, out.getvalue(), err.getvalue()

    def policy(self) -> dict:
        return yaml.safe_load((self.out / "policy-global.yml").read_text(encoding="utf-8"))

    def semgrep_ids(self, name: str) -> set:
        data = yaml.safe_load((self.out / "semgrep" / name).read_text(encoding="utf-8"))
        return {r["id"] for r in data["rules"]}

    # --- defaults only ------------------------------------------------------
    def test_no_project_settings_means_the_defaults(self):
        rc, out, _ = self.run_main(Path(self.tmp.name) / "absent")
        self.assertEqual(rc, 0)
        self.assertIn("none (oss-analyzer defaults only)", out)
        self.assertIn("allow", self.policy()["licenses"])  # policy-licenses.yml pulled in
        self.assertEqual(sorted(p.name for p in (self.out / "semgrep").iterdir()),
                         ["policy-semgrep.yml"])
        self.assertEqual((self.out / "policy-gitleaks.toml").read_text(encoding="utf-8"),
                         (SECURITY / "policy-gitleaks.toml").read_text(encoding="utf-8"))
        self.assertIn("p/default\n", (self.out / "semgrep-packs.txt").read_text(encoding="utf-8"))

    def test_settings_identical_to_the_defaults_are_ignored(self):
        # oss-analyzer's own self-test: its security/ folder *is* the defaults.
        rc, out, _ = self.run_main(SECURITY)
        self.assertEqual(rc, 0)
        self.assertIn("policy-gitleaks.toml (identical to the default: ignored)", out)
        self.assertIn("policy:   oss-analyzer default |", out)
        self.assertNotIn("::warning::", out)  # no rule "defined by both"
        self.assertEqual([p.name for p in (self.out / "semgrep").iterdir()], ["policy-semgrep.yml"])
        self.assertFalse((self.out / "policy-gitleaks.base.toml").exists())

    # --- policy and licenses ------------------------------------------------
    def test_project_policy_licenses_alone_reclassifies_the_base(self):
        self.write("policy-licenses.yml", "deny: [MIT]\n")
        self.assertEqual(self.run_main()[0], 0)
        lic = self.policy()["licenses"]
        self.assertIn("MIT", lic["deny"])
        self.assertNotIn("MIT", lic["allow"])

    def test_typo_in_project_policy_is_logged(self):
        self.write("policy-global.yml", "licenses:\n  fail_on_reviews: true\n")
        rc, out, _ = self.run_main()
        self.assertEqual(rc, 0)
        self.assertIn("::warning:: policy-global.yml: licenses.fail_on_reviews: unknown key", out)

    def test_invalid_value_in_project_policy_stops_prepare(self):
        self.write("policy-global.yml", "vulnerabilities:\n  fail_on: hgih\n")
        rc, _, err = self.run_main()
        self.assertEqual(rc, 2)
        self.assertIn("vulnerabilities.fail_on: 'hgih'", err)

    def test_project_policy_merges_on_top(self):
        self.write("policy-global.yml", "vulnerabilities:\n  fail_on: critical\n")
        rc, out, _ = self.run_main()
        self.assertEqual(rc, 0)
        self.assertEqual(self.policy()["vulnerabilities"]["fail_on"], "critical")
        self.assertIn("oss-analyzer default + project", out)

    # --- Semgrep ------------------------------------------------------------
    def test_project_rules_run_in_addition_and_duplicates_warn(self):
        self.write("policy-semgrep.yml", "rules:\n"
                   "  - {id: project-rule, languages: [python], severity: INFO, message: m, pattern: x}\n"
                   "  - {id: go-ignored-error, languages: [go], severity: INFO, message: m, pattern: y}\n")
        rc, out, _ = self.run_main()
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(p.name for p in (self.out / "semgrep").iterdir()),
                         ["policy-semgrep.project.yml", "policy-semgrep.yml"])
        self.assertIn("go-ignored-error", self.semgrep_ids("policy-semgrep.yml"))
        self.assertIn("'go-ignored-error' is defined by both", out)

    def test_disabled_rules_drop_ours_and_unknown_ids_warn(self):
        self.write("policy-global.yml", "sast:\n  disabled_rules: [go-ignored-error, no-such-rule]\n")
        rc, out, _ = self.run_main()
        self.assertEqual(rc, 0)
        ids = self.semgrep_ids("policy-semgrep.yml")
        self.assertNotIn("go-ignored-error", ids)
        self.assertIn("go-sql-string-concat", ids)
        self.assertIn("'no-such-rule' isn't one of oss-analyzer's rules", out)

    def test_inherit_rules_false_runs_the_project_rules_alone(self):
        self.write("policy-global.yml", "sast:\n  inherit_rules: false\n")
        self.write("policy-semgrep.yml", "rules: []\n")
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual([p.name for p in (self.out / "semgrep").iterdir()],
                         ["policy-semgrep.project.yml"])

    def test_registry_packs_list_replaces_the_base(self):
        self.write("policy-global.yml", "sast:\n  registry_packs: [p/python]\n")
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual((self.out / "semgrep-packs.txt").read_text(encoding="utf-8"), "p/python\n")

    def test_not_a_rules_file_is_an_error(self):
        self.write("policy-semgrep.yml", "- not: rules\n")
        rc, _, err = self.run_main()
        self.assertEqual(rc, 2)
        self.assertIn("not a Semgrep rules file", err)

    # --- Gitleaks -----------------------------------------------------------
    def test_project_gitleaks_extends_ours(self):
        self.write("policy-gitleaks.toml", 'title = "Project"\n\n[[rules]]\nid = "p"\nregex = "x"\n')
        rc, out, _ = self.run_main()
        self.assertEqual(rc, 0)
        composed = tomllib.loads((self.out / "policy-gitleaks.toml").read_text(encoding="utf-8"))
        self.assertEqual(composed["title"], "Project")  # root key not captured by [extend]
        self.assertEqual(composed["extend"]["path"], (self.out / "policy-gitleaks.base.toml").as_posix())
        self.assertTrue((self.out / "policy-gitleaks.base.toml").is_file())
        self.assertIn("extending oss-analyzer's", out)

    def test_project_gitleaks_with_its_own_extend_is_refused(self):
        self.write("policy-gitleaks.toml", "[extend]\nuseDefault = true\n")
        rc, _, err = self.run_main()
        self.assertEqual(rc, 2)
        self.assertIn("has its own [extend]", err)

    def test_secrets_inherit_rules_false_uses_the_project_file_alone(self):
        self.write("policy-global.yml", "secrets:\n  inherit_rules: false\n")
        self.write("policy-gitleaks.toml", "[extend]\nuseDefault = true\n")
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual((self.out / "policy-gitleaks.toml").read_text(encoding="utf-8"),
                         "[extend]\nuseDefault = true\n")
        self.assertFalse((self.out / "policy-gitleaks.base.toml").exists())

    def test_non_boolean_inherit_flag_is_an_error(self):
        self.write("policy-global.yml", "secrets:\n  inherit_rules: 'no'\n")
        rc, _, err = self.run_main()
        self.assertEqual(rc, 2)
        self.assertIn("secrets.inherit_rules: expected true or false", err)


if __name__ == "__main__":
    unittest.main()
