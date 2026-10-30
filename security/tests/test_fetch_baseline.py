# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""Unit tests of security/scripts/fetch_baseline.py: the URL it builds, and
that it never fails the job, whatever the API answers."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fetch_baseline  # noqa: E402

CI_ENV = {"CI_API_V4_URL": "https://gitlab.example/api/v4", "CI_PROJECT_ID": "42",
          "CI_JOB_TOKEN": "job-token"}


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FetchBaselineTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.output = Path(tmp.name, "baseline", "security-report.json")

    def run_main(self, urlopen, env=CI_ENV):
        argv = ["fetch_baseline.py", "--ref", "release/1.x", "--job", "osa_report_aggregate-web",
                "--path", "security-reports/security-report.json", "--output", str(self.output)]
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.dict(os.environ, env, clear=True), \
                mock.patch("urllib.request.OpenerDirector.open",
                           lambda _self, request, timeout: urlopen(request, timeout)), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = fetch_baseline.main()
        return code, out.getvalue()

    def test_token_is_not_sent_to_another_host(self):
        handler = fetch_baseline.SameHostRedirects()
        request = urllib.request.Request("https://gitlab.example/api/v4/x",
                                         headers={"JOB-TOKEN": "job-token"})
        for target, kept in (("https://gitlab.example/other", True),
                             ("https://bucket.s3.example/presigned", False)):
            with self.subTest(target=target):
                new = handler.redirect_request(request, None, 302, "Found", {}, target)
                self.assertEqual(new.has_header("Job-token"), kept)

    def test_fork_merge_request_reads_the_target_project(self):
        seen = []
        self.run_main(lambda request, timeout: seen.append(request.full_url) or FakeResponse(b"{}"),
                      env={**CI_ENV, "CI_MERGE_REQUEST_PROJECT_ID": "7"})
        self.assertIn("/projects/7/jobs/artifacts/", seen[0])

    def test_url_encodes_the_ref_and_the_job(self):
        self.assertEqual(
            fetch_baseline.baseline_url("https://gitlab.example/api/v4/", "42", "release/1.x",
                                        "./security-reports/security-report.json", "osa job"),
            "https://gitlab.example/api/v4/projects/42/jobs/artifacts/release%2F1.x"
            "/raw/security-reports/security-report.json?job=osa%20job")

    def test_writes_the_report_with_the_job_token(self):
        seen = {}

        def urlopen(request, timeout):
            seen["url"], seen["token"] = request.full_url, request.get_header("Job-token")
            return FakeResponse(b'{"findings": []}')

        code, _ = self.run_main(urlopen)
        self.assertEqual(code, 0)
        self.assertEqual(self.output.read_text(encoding="utf-8"), '{"findings": []}')
        self.assertEqual(seen["token"], "job-token")
        self.assertIn("/jobs/artifacts/release%2F1.x/raw/", seen["url"])

    def test_no_baseline_is_a_warning_not_a_failure(self):
        def not_found(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)

        for urlopen in (not_found, lambda r, timeout: FakeResponse(b"<html>")):
            with self.subTest(urlopen=urlopen):
                code, out = self.run_main(urlopen)
                self.assertEqual(code, 0)
                self.assertIn("No baseline", out)
                self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
