# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""Unit tests of security/scripts/gitlab_reports.py (GitLab native formats)."""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import gitlab_reports as gl  # noqa: E402


def finding(**over) -> dict:
    f = {"category": "sast", "tool": "semgrep", "id": "rule.x", "title": "A finding",
         "severity": "high", "location": "src/app.py:42", "status": "blocking"}
    f.update(over)
    return f


class SplitLocationTest(unittest.TestCase):
    def test_split_location(self):
        for location, expected in (
                ("src/app.py:42", ("src/app.py", 42)),
                ("src/app.py", ("src/app.py", None)),
                ("src/app.py:", ("src/app.py", None)),        # trailing colon dropped
                ("a:b", ("a:b", None)),                       # non-numeric: part of the path
                ("C:\\src\\app.py:7", ("C:\\src\\app.py", 7))):  # Windows drive letter
            with self.subTest(location=location):
                self.assertEqual(gl.split_location(location), expected)


class IdentifierTest(unittest.TestCase):
    def test_identifier_type_by_prefix(self):
        for ident, kind in (("CVE-2021-44228", "cve"), ("GHSA-xxxx-yyyy-zzzz", "ghsa"),
                            ("FOO-1", "oss-analyzer")):
            with self.subTest(ident=ident):
                self.assertEqual(gl.identifier(ident)["type"], kind)


class CodeQualityTest(unittest.TestCase):
    def test_blocking_finding_is_a_blocker_whatever_its_severity(self):
        issue = gl.code_quality_issue(finding(severity="low", status="blocking"))
        self.assertEqual(issue["severity"], "blocker")

    def test_non_blocking_finding_maps_its_severity(self):
        issue = gl.code_quality_issue(finding(severity="high", status="exception"))
        self.assertEqual(issue["severity"], "major")

    def test_line_defaults_to_1_and_path_has_no_trailing_colon(self):
        issue = gl.code_quality_issue(finding(location="src/app.py:"))
        self.assertEqual(issue["location"], {"path": "src/app.py", "lines": {"begin": 1}})

    def test_findings_without_commit_or_columns_keep_their_fingerprint(self):
        # Unchanged formula: GitLab doesn't re-identify existing SAST findings.
        import hashlib
        self.assertEqual(gl.code_quality_issue(finding())["fingerprint"],
                         hashlib.md5(b"sast|rule.x|src/app.py:42").hexdigest())

    def test_secrets_on_one_line_or_in_two_commits_dont_collide(self):
        def secret(**over):
            base = dict(category="secret", tool="gitleaks", id="generic-api-key",
                        location=".env:3", commit="a1", extra={"start_col": 5, "end_col": 30})
            base.update(over)
            return gl.code_quality_issue(finding(**base))["fingerprint"]
        prints = {secret(), secret(extra={"start_col": 40, "end_col": 70}), secret(commit="b2")}
        self.assertEqual(len(prints), 3)
        self.assertEqual(secret(), secret())


class SecretVulnerabilityTest(unittest.TestCase):
    def test_commit_from_the_finding_else_the_environment(self):
        with mock.patch.dict(os.environ, {"CI_COMMIT_SHA": "env-sha"}):
            with_commit = gl.secret_vulnerability(finding(tool="gitleaks", commit="abc"))
            without = gl.secret_vulnerability(finding(tool="gitleaks"))
        self.assertEqual(with_commit["location"]["commit"]["sha"], "abc")
        self.assertEqual(without["location"]["commit"]["sha"], "env-sha")

    def test_location_without_line_has_no_line_range(self):
        vuln = gl.secret_vulnerability(finding(tool="gitleaks", location="secrets/.env:"))
        self.assertEqual(vuln["location"]["file"], "secrets/.env")
        self.assertNotIn("start_line", vuln["location"])


class DependencyTest(unittest.TestCase):
    def test_only_grype_and_osv_findings_are_dependency_findings(self):
        self.assertTrue(gl.is_dependency_finding(finding(category="vuln", tool="grype+osv")))
        self.assertFalse(gl.is_dependency_finding(finding(category="vuln", tool="trivy")))
        self.assertFalse(gl.is_dependency_finding(finding(category="sast", tool="grype")))

    def test_title_without_a_version(self):
        vuln = gl.dependency_vulnerability(
            finding(category="vuln", tool="grype", id="CVE-1", title="lodash",
                    location="lodash", status="blocking"))
        self.assertEqual(vuln["location"]["dependency"],
                         {"package": {"name": "lodash"}, "version": ""})

    def test_fixed_version_becomes_the_solution(self):
        vuln = gl.dependency_vulnerability(
            finding(category="vuln", tool="grype", id="CVE-1", title="lodash 4.17.0",
                    location="lodash", fixed="4.17.21"))
        self.assertEqual(vuln["solution"], "Upgrade lodash to 4.17.21.")


class SecurityReportTest(unittest.TestCase):
    def test_an_empty_report_is_still_a_valid_report(self):
        report = gl.security_report("secret_detection", [], "2026-01-01T00:00:00")
        self.assertEqual(report["version"], gl.SCHEMA_VERSION)
        self.assertEqual(report["vulnerabilities"], [])


if __name__ == "__main__":
    unittest.main()
