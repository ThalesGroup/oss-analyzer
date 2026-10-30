# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""The GitLab native reports written by security/scripts/gitlab_reports.py,
validated against GitLab's official JSON schemas of the version they
declare (SCHEMA_VERSION), vendored under schemas/gitlab-<version>/ from
gitlab-org/security-products/security-report-schemas (MIT). A report that
doesn't validate is silently ignored by GitLab: this pins what used to be
checked by hand. Runs where jsonschema is installed (the oss-analyzer
image, i.e. the test:unit job); skipped elsewhere."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import gitlab_reports as gl  # noqa: E402

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

SCHEMAS = Path(__file__).resolve().parent / "schemas" / f"gitlab-{gl.SCHEMA_VERSION}"

# What aggregate_report.py writes, covering the shapes that reach the
# reports: a dependency vulnerability seen by two scanners (aliases, fix,
# manifest), one without fix or manifest, each status, and secrets with
# and without commit and line.
FINDINGS = [
    {"tool": "grype+osv", "id": "GHSA-jfh8-c2jp-5v3q", "severity": "critical",
     "title": "log4j-core 2.14.1", "location": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
     "fixed": "2.15.0", "category": "vuln", "file": "java/pom.xml",
     "aliases": ["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"], "status": "blocking",
     "description": "Remote code execution through JNDI lookups."},
    {"tool": "grype", "id": "CVE-2020-0001", "severity": "unknown", "title": "somepkg",
     "location": "pkg:npm/somepkg", "fixed": None, "category": "vuln",
     "status": "sans-correctif"},
    {"tool": "osv", "id": "PYSEC-2024-1", "severity": "medium", "title": "django 2.2.0",
     "location": "pkg:pypi/django@2.2.0", "fixed": "2.2.24", "category": "vuln",
     "status": "exception"},
    {"tool": "osv", "id": "RUSTSEC-2020-0071", "severity": "low", "title": "time 0.1.43",
     "location": "pkg:cargo/time@0.1.43", "fixed": "0.2.23", "category": "vuln",
     "status": "would-block"},
    {"tool": "gitleaks", "id": "aws-access-token", "severity": "critical",
     "title": "AWS access token", "location": "secrets/.env:3", "category": "secret",
     "commit": "0123456789abcdef0123456789abcdef01234567", "status": "blocking",
     "extra": {"start_line": 3, "end_line": 3, "start_col": 5, "end_col": 25}},
    {"tool": "gitleaks", "id": "private-key", "severity": "critical", "title": "Private key",
     "location": "secrets/id_rsa.fixture:", "category": "secret", "status": "info"},
]


@unittest.skipUnless(jsonschema, "jsonschema not installed (it is in the oss-analyzer image)")
class GitLabReportSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        out = Path(tmp.name)
        (out / "security-report.json").write_text(json.dumps({"findings": FINDINGS}),
                                                  encoding="utf-8")
        argv = ["gitlab_reports.py", "--report", str(out / "security-report.json"),
                "--output-dir", str(out)]
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
            assert gl.main() == 0
        cls.reports = {name: json.loads((out / name).read_text(encoding="utf-8"))
                       for name in ("gl-dependency-scanning-report.json",
                                    "gl-secret-detection-report.json")}

    def validate(self, report: str, schema: str):
        schema_doc = json.loads((SCHEMAS / schema).read_text(encoding="utf-8"))
        errors = sorted(jsonschema.Draft7Validator(schema_doc).iter_errors(self.reports[report]),
                        key=lambda e: list(e.path))
        self.assertEqual([f"{list(e.path)}: {e.message}" for e in errors], [])

    def test_schemas_of_the_declared_version_are_vendored(self):
        self.assertTrue((SCHEMAS / "dependency-scanning-report-format.json").is_file(),
                        f"vendor GitLab's {gl.SCHEMA_VERSION} schemas under {SCHEMAS}")

    def test_dependency_scanning_report_matches_gitlab_schema(self):
        self.assertEqual(len(self.reports["gl-dependency-scanning-report.json"]["vulnerabilities"]), 4)
        self.validate("gl-dependency-scanning-report.json", "dependency-scanning-report-format.json")

    def test_secret_detection_report_matches_gitlab_schema(self):
        self.assertEqual(len(self.reports["gl-secret-detection-report.json"]["vulnerabilities"]), 2)
        self.validate("gl-secret-detection-report.json", "secret-detection-report-format.json")


if __name__ == "__main__":
    unittest.main()
