# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""Unit tests of security/scripts/aggregate_report.py: coverage gaps of the
scanners the pipeline expected (--expect) and their effect on the verdict,
the new-findings-only gate (--gate-scope new), and the deduplication of
dependency findings (normalized purls, IDs and aliases)."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import aggregate_report as agg  # noqa: E402

ALL_SCANNERS = "grype,osv,semgrep,gitleaks,licenses,trivy"
# What each scanner writes when it ran and found nothing.
EMPTY_REPORTS = {
    "grype.json": {"matches": []},
    "osv.json": {"results": []},
    "semgrep.json": {"results": []},
    "gitleaks.json": [],
    "licenses.json": {"summary": {}},
    "trivy-iac.json": {"SchemaVersion": 2},
}
AUDIT_POLICY = {section: {"mode": "audit"}
                for section in ("vulnerabilities", "sast", "secrets", "licenses")}


class WorkDirTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def write_reports(self, *, skip=()):
        for name, content in EMPTY_REPORTS.items():
            if name not in skip:
                (self.dir / name).write_text(json.dumps(content), encoding="utf-8")

    def run_main(self, policy: dict, *extra: str):
        policy_file = self.dir / "policy-global.yml"
        policy_file.write_text(yaml.safe_dump(policy), encoding="utf-8")
        argv = ["aggregate_report.py", "--input-dir", str(self.dir),
                "--policy", str(policy_file), *extra]
        with mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            code = agg.main()
        report = json.loads((self.dir / "security-report.json").read_text(encoding="utf-8"))
        return code, report


class ReportProblemTest(WorkDirTest):
    def problem(self, content=None, shape=None):
        path = self.dir / "r.json"
        if content is not None:
            path.write_text(content, encoding="utf-8")
        return agg.report_problem(path, shape)

    def test_missing_empty_or_unreadable(self):
        for content, reason in ((None, "report not produced"), ("", "report empty"),
                                ("{not json", "report unreadable")):
            with self.subTest(content=content):
                self.assertEqual(self.problem(content), reason)

    def test_a_scan_with_no_finding_is_not_a_problem(self):
        for name, content in EMPTY_REPORTS.items():
            tool = next(t for t, (f, _s, _sh) in agg.EXPECTED_REPORTS.items() if f == name)
            self.assertIsNone(self.problem(json.dumps(content), agg.EXPECTED_REPORTS[tool][2]),
                              name)

    def test_placeholder_or_error_document_is_not_a_scan(self):
        # What a failed scanner may leave: valid JSON, but not its report.
        for content, shape in (("{}", "matches"), ("null", "results"),
                               ('{"error": "rate limited"}', "results"),
                               ('{"findings": []}', "list"), ("[]", "summary")):
            with self.subTest(content=content, shape=shape):
                self.assertTrue(self.problem(content, shape).startswith("not a scan report"))

    def test_without_shape_any_json_passes(self):
        self.assertIsNone(self.problem("{}"))


class ExpectedGapsTest(WorkDirTest):
    def test_audit_mode_of_the_scanner_category_does_not_block(self):
        self.write_reports(skip=("semgrep.json", "gitleaks.json"))
        policy = {"sast": {"mode": "audit"}, "secrets": {"mode": "enforce"}}
        gaps = {g["tool"]: g["blocking"]
                for g in agg.expected_gaps(self.dir, ["semgrep", "gitleaks"], policy)}
        self.assertEqual(gaps, {"semgrep": False, "gitleaks": True})


class VerdictTest(WorkDirTest):
    def test_complete_coverage_passes(self):
        self.write_reports()
        code, report = self.run_main({}, "--expect", ALL_SCANNERS)
        self.assertEqual(code, 0)
        self.assertFalse(report["failed"])
        self.assertEqual(report["coverage_blocking"], 0)
        self.assertEqual(report["coverage_gaps"], [])

    def test_missing_report_fails_the_gate_in_enforce_mode(self):
        self.write_reports(skip=("grype.json",))
        code, report = self.run_main({}, "--expect", ALL_SCANNERS)
        self.assertEqual(code, 1)
        self.assertTrue(report["failed"])
        self.assertEqual(report["blocking"], 0)  # no finding: the gap alone blocks
        self.assertEqual(report["coverage_blocking"], 1)
        self.assertEqual([g["tool"] for g in report["coverage_gaps"]], ["grype"])
        markdown = (self.dir / "security-report.md").read_text(encoding="utf-8")
        self.assertIn("Incomplete coverage", markdown)
        self.assertIn("PIPELINE BLOCKED", markdown)

    def test_placeholder_report_fails_the_gate_like_a_missing_one(self):
        self.write_reports()
        (self.dir / "osv.json").write_text("{}", encoding="utf-8")
        code, report = self.run_main({}, "--expect", ALL_SCANNERS)
        self.assertEqual(code, 1)
        self.assertEqual([(g["tool"], g["reason"]) for g in report["coverage_gaps"]],
                         [("osv", "not a scan report (no `results` key)")])

    def test_missing_report_only_warns_in_audit_mode(self):
        self.write_reports(skip=("grype.json", "licenses.json"))
        code, report = self.run_main(AUDIT_POLICY, "--expect", ALL_SCANNERS)
        self.assertEqual(code, 0)
        self.assertFalse(report["failed"])
        self.assertEqual(report["coverage_blocking"], 0)
        self.assertEqual(len(report["coverage_gaps"]), 2)
        markdown = (self.dir / "security-report.md").read_text(encoding="utf-8")
        self.assertIn("Reduced coverage", markdown)
        self.assertNotIn("Incomplete coverage", markdown)

    def test_without_expect_a_missing_report_changes_nothing(self):
        # Local runs (analyze-archive.sh) don't pass --expect.
        code, report = self.run_main({})
        self.assertEqual(code, 0)
        self.assertIsNone(report["coverage_gaps"])

    def test_scanners_not_expected_are_not_required(self):
        self.write_reports(skip=("osv.json", "gitleaks.json"))
        code, _ = self.run_main({}, "--expect", "grype,semgrep,licenses")
        self.assertEqual(code, 0)

    def test_unknown_scanner_name_is_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            self.run_main({}, "--expect", "grype,snyk")
        self.assertEqual(ctx.exception.code, 2)


def grype_match(cve: str, name: str = "lib", version: str = "1.0") -> dict:
    """A fixable High vulnerability: blocks under the default policy."""
    return {"vulnerability": {"id": cve, "severity": "High",
                              "fix": {"state": "fixed", "versions": ["9.9"]}},
            "artifact": {"name": name, "version": version,
                         "purl": f"pkg:npm/{name}@{version}"}}


def semgrep_result(rule: str, path: str, line: int) -> dict:
    return {"check_id": rule, "path": path, "start": {"line": line},
            "extra": {"severity": "ERROR", "message": "bad"}}


class GateScopeTest(WorkDirTest):
    """--gate-scope new: only what the merge request brings blocks."""

    def write(self, grype=(), semgrep=(), denied=(), version="1"):
        self.write_reports()
        (self.dir / "grype.json").write_text(json.dumps({"matches": list(grype)}),
                                             encoding="utf-8")
        (self.dir / "semgrep.json").write_text(json.dumps({"results": list(semgrep)}),
                                               encoding="utf-8")
        components = [{"name": n, "version": version, "purl": f"pkg:npm/{n}@{version}",
                       "verdict": "deny"} for n in denied]
        (self.dir / "licenses.json").write_text(json.dumps(
            {"summary": {"deny": len(components)}, "failed": bool(components),
             "would_fail": bool(components), "components": components}), encoding="utf-8")

    def baseline(self, **reports) -> Path:
        """Runs the plain gate on `reports` and keeps its report as the baseline."""
        self.write(**reports)
        self.run_main({})
        path = self.dir / "baseline.json"
        path.write_bytes((self.dir / "security-report.json").read_bytes())
        return path

    def run_new(self, baseline: Path | None, merge_request=True):
        args = ["--gate-scope", "new", "--baseline-ref", "main"]
        if merge_request:
            args.append("--merge-request")
        if baseline:
            args += ["--baseline", str(baseline)]
        return self.run_main({}, *args)

    def test_finding_already_on_the_target_branch_does_not_block(self):
        base = self.baseline(grype=[grype_match("CVE-1")])
        self.write(grype=[grype_match("CVE-1")])
        code, report = self.run_new(base)
        self.assertEqual(code, 0)
        self.assertEqual((report["blocking"], report["existing"]), (0, 1))
        self.assertEqual(report["findings"][0]["status"], "existing")
        markdown = (self.dir / "security-report.md").read_text(encoding="utf-8")
        self.assertIn("Already on the target branch", markdown)
        self.assertIn("nothing new", markdown)

    def test_new_finding_blocks(self):
        base = self.baseline(grype=[grype_match("CVE-1")])
        self.write(grype=[grype_match("CVE-1"), grype_match("CVE-2")])
        code, report = self.run_new(base)
        self.assertEqual(code, 1)
        self.assertEqual((report["blocking"], report["existing"]), (1, 1))
        blocking = [f["id"] for f in report["findings"] if f["status"] == "blocking"]
        self.assertEqual(blocking, ["CVE-2"])

    def test_upgraded_component_with_the_same_cve_is_new(self):
        base = self.baseline(grype=[grype_match("CVE-1", version="1.0")])
        self.write(grype=[grype_match("CVE-1", version="1.1")])
        self.assertEqual(self.run_new(base)[0], 1)

    def test_secret_is_never_matched_with_the_baseline(self):
        # A rotated credential in the same file must not pass for the old one.
        secret = [{"RuleID": "generic-api-key", "File": "config.py", "StartLine": 10}]
        self.write_reports()
        (self.dir / "gitleaks.json").write_text(json.dumps(secret), encoding="utf-8")
        self.run_main({})
        base = self.dir / "baseline.json"
        base.write_bytes((self.dir / "security-report.json").read_bytes())
        code, report = self.run_new(base)
        self.assertEqual((code, report["existing"]), (1, 0))

    def test_moved_line_is_not_new_but_a_second_occurrence_is(self):
        base = self.baseline(semgrep=[semgrep_result("rule", "app.py", 10)])
        self.write(semgrep=[semgrep_result("rule", "app.py", 42)])
        self.assertEqual(self.run_new(base)[0], 0)
        self.write(semgrep=[semgrep_result("rule", "app.py", 42),
                            semgrep_result("rule", "app.py", 50)])
        code, report = self.run_new(base)
        self.assertEqual((code, report["blocking"], report["existing"]), (1, 1, 1))

    def test_without_baseline_a_merge_request_gets_the_full_gate(self):
        self.write(grype=[grype_match("CVE-1")])
        code, report = self.run_new(self.dir / "missing.json")
        self.assertEqual(code, 1)
        self.assertEqual(report["gate_scope"]["state"], "full")
        markdown = (self.dir / "security-report.md").read_text(encoding="utf-8")
        self.assertIn("no report of `main` to compare with", markdown)

    def test_outside_a_merge_request_nothing_blocks_but_coverage(self):
        self.write(grype=[grype_match("CVE-1")], denied=["gpl-lib"])
        code, report = self.run_new(None, merge_request=False)
        self.assertEqual(code, 0)
        self.assertEqual(report["gate_scope"]["state"], "report")
        self.assertEqual(report["would_block"], 2)  # the CVE + the license gate
        (self.dir / "grype.json").unlink()
        code, report = self.run_main({}, "--gate-scope", "new", "--expect", "grype")
        self.assertEqual((code, report["coverage_blocking"]), (1, 1))

    def test_license_violation_already_on_the_target_branch_does_not_block(self):
        base = self.baseline(denied=["gpl-lib"])
        self.assertEqual(json.loads(base.read_text(encoding="utf-8"))["license_violations"],
                         ["pkg:npm/gpl-lib"])  # without its version
        self.write(denied=["gpl-lib"], version="2")  # a version bump isn't new
        code, report = self.run_new(base)
        self.assertEqual((code, report["existing"], report["new_license_violations"]),
                         (0, 1, []))
        self.write(denied=["gpl-lib", "agpl-lib"])
        code, report = self.run_new(base)
        self.assertEqual((code, report["new_license_violations"]), (1, ["pkg:npm/agpl-lib"]))

    def test_baseline_without_license_violations_keeps_licenses_under_the_full_gate(self):
        base = self.baseline(denied=["gpl-lib"])
        old = json.loads(base.read_text(encoding="utf-8"))
        del old["license_violations"]
        base.write_text(json.dumps(old), encoding="utf-8")
        self.write(denied=["gpl-lib"])
        code, report = self.run_new(base)
        self.assertEqual((code, report["new_license_violations"]), (1, None))

    def test_baseline_with_raw_purls_still_matches(self):
        # Written before purls were normalized: `?type=jar` kept.
        base = self.baseline(grype=[grype_match("CVE-1")])
        old = json.loads(base.read_text(encoding="utf-8"))
        old["findings"][0]["location"] += "?type=jar"
        base.write_text(json.dumps(old), encoding="utf-8")
        self.write(grype=[grype_match("CVE-1")])
        code, report = self.run_new(base)
        self.assertEqual((code, report["existing"]), (0, 1))


def maven_match(ghsa: str, purl: str, severity: str = "High", related=("CVE-1",)) -> dict:
    """A Grype match on jackson-databind 2.9.8, as one SBOM entry gives it."""
    return {"vulnerability": {"id": ghsa, "severity": severity,
                              "fix": {"state": "fixed", "versions": ["2.9.10"]}},
            "relatedVulnerabilities": [{"id": r} for r in related],
            "artifact": {"name": "jackson-databind", "version": "2.9.8", "purl": purl}}


def osv_result(name: str, version: str, ecosystem: str, *vulns: dict) -> dict:
    return {"results": [{"source": {"path": "/src/manifest"}, "packages": [
        {"package": {"name": name, "version": version, "ecosystem": ecosystem},
         "vulnerabilities": list(vulns)}]}]}


JACKSON = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8"


class LicenseComponentsTest(unittest.TestCase):
    def test_only_components_not_allowed_are_kept(self):
        lic = {"components": [
            {"name": "a", "version": "1", "purl": "pkg:npm/a@1", "licenses": ["MIT"],
             "verdict": "allow", "exempted": False},
            {"name": "b", "version": "2", "purl": "pkg:npm/b@2", "licenses": [],
             "verdict": "review", "exempted": False},
            {"name": "c", "version": "3", "purl": "pkg:npm/c@3", "licenses": ["AGPL-3.0-only"],
             "verdict": "deny", "exempted": False}]}
        self.assertEqual(agg.license_components(lic), [
            {"name": "b", "version": "2", "purl": "pkg:npm/b@2", "licenses": [], "verdict": "review"},
            {"name": "c", "version": "3", "purl": "pkg:npm/c@3", "licenses": ["AGPL-3.0-only"],
             "verdict": "deny"}])

    def test_no_license_report_gives_an_empty_list(self):
        self.assertEqual(agg.license_components({}), [])


class SemgrepTitleTest(unittest.TestCase):
    def test_long_message_is_cut_at_a_word_and_kept_whole_as_description(self):
        message = "Detected user input entering a subprocess call unsafely. " * 4
        [f] = agg.parse_semgrep({"results": [semgrep_result("rule", "app.py", 3)
                                             | {"extra": {"severity": "ERROR", "message": message}}]})
        self.assertTrue(f["title"].endswith("…"))
        self.assertLessEqual(len(f["title"]), 161)
        self.assertTrue(message.startswith(f["title"][:-1]))
        self.assertEqual(f["description"], message.strip())

    def test_short_message_has_no_description(self):
        [f] = agg.parse_semgrep({"results": [semgrep_result("rule", "app.py", 3)]})
        self.assertEqual((f["title"], "description" in f), ("bad", False))


class NormalizePurlTest(unittest.TestCase):
    def test_qualifiers_and_subpath_are_dropped(self):
        self.assertEqual(agg.normalize_purl(JACKSON + "?type=jar#sub"), JACKSON)

    def test_percent_encoding_is_decoded(self):
        self.assertEqual(agg.normalize_purl("pkg:golang/github.com/x/jwt-go@v3.2.0%2Bincompatible"),
                         "pkg:golang/github.com/x/jwt-go@v3.2.0+incompatible")
        self.assertEqual(agg.normalize_purl("pkg:npm/%40angular/core@1.0.0"),
                         "pkg:npm/@angular/core@1.0.0")

    def test_a_location_that_is_not_a_purl_is_kept(self):
        self.assertEqual(agg.normalize_purl("app/Dockerfile"), "app/Dockerfile")


class DeduplicationTest(WorkDirTest):
    def run_with(self, grype=(), osv=None, trivy=None, policy=None):
        self.write_reports()
        (self.dir / "grype.json").write_text(json.dumps({"matches": list(grype)}), encoding="utf-8")
        if osv is not None:
            (self.dir / "osv.json").write_text(json.dumps(osv), encoding="utf-8")
        if trivy is not None:
            (self.dir / "trivy-image.json").write_text(json.dumps(trivy), encoding="utf-8")
        _code, report = self.run_main(policy or {})
        return [f for f in report["findings"] if f["category"] == "vuln"]

    def test_one_advisory_seen_through_two_sbom_entries_and_osv_is_one_finding(self):
        findings = self.run_with(
            grype=[maven_match("GHSA-a", JACKSON), maven_match("GHSA-a", JACKSON + "?type=jar")],
            # OSV's title differs: com.fasterxml.jackson.core:jackson-databind 2.9.8.
            osv=osv_result("com.fasterxml.jackson.core:jackson-databind", "2.9.8", "Maven",
                           {"id": "GHSA-a", "aliases": ["CVE-1"]}))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual((f["id"], f["tool"], f["location"], f["severity"]),
                         ("GHSA-a", "grype+osv", JACKSON, "high"))
        self.assertEqual(f["aliases"], ["CVE-1"])

    def test_same_vulnerability_under_two_ids_is_one_finding(self):
        # Grype's GHSA and OSV's PYSEC, without severity: aliases in common.
        findings = self.run_with(
            grype=[{"vulnerability": {"id": "GHSA-p", "severity": "Critical",
                                      "fix": {"state": "fixed", "versions": ["2.2.10"]}},
                    "relatedVulnerabilities": [{"id": "CVE-2"}],
                    "artifact": {"name": "django", "version": "2.2.0",
                                 "purl": "pkg:pypi/django@2.2.0"}}],
            osv=osv_result("django", "2.2.0", "PyPI",
                           {"id": "PYSEC-1", "aliases": ["CVE-2", "GHSA-p"]}))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual((f["id"], f["severity"], f["tool"]), ("GHSA-p", "critical", "grype+osv"))
        self.assertEqual(f["aliases"], ["CVE-2", "PYSEC-1"])

    def test_distinct_advisories_on_one_component_stay_apart(self):
        findings = self.run_with(grype=[maven_match("GHSA-a", JACKSON, related=("CVE-1",)),
                                        maven_match("GHSA-b", JACKSON, related=("CVE-2",))])
        self.assertEqual(sorted(f["id"] for f in findings), ["GHSA-a", "GHSA-b"])

    def test_one_cve_on_two_packages_of_an_image_stays_two_findings(self):
        trivy = {"Results": [{"Target": "app:1.0", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-3", "Severity": "HIGH", "PkgName": name,
             "InstalledVersion": "1", "FixedVersion": "2"} for name in ("libssl", "openssl")]}]}
        self.assertEqual(len(self.run_with(trivy=trivy)), 2)

    def test_most_severe_first(self):
        findings = self.run_with(grype=[maven_match("GHSA-l", JACKSON, "Low", ("CVE-L",)),
                                        maven_match("GHSA-c", JACKSON, "Critical", ("CVE-C",))])
        self.assertEqual([f["severity"] for f in findings], ["critical", "low"])

    def test_exception_on_an_alias_applies_to_the_merged_finding(self):
        policy = {"vulnerabilities": {"exceptions": [
            {"id": "PYSEC-1", "expires": date(2099, 1, 1)}]}}
        findings = self.run_with(
            grype=[maven_match("GHSA-p", JACKSON, related=("CVE-2",))],
            osv=osv_result("com.fasterxml.jackson.core:jackson-databind", "2.9.8", "Maven",
                           {"id": "PYSEC-1", "aliases": ["CVE-2"]}),
            policy=policy)
        self.assertEqual([(f["id"], f["status"]) for f in findings], [("GHSA-p", "exception")])


if __name__ == "__main__":
    unittest.main()
