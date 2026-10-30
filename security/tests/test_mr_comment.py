# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""Unit tests of security/scripts/mr_comment.py: the comment's content, and
its upsert against a fake GitLab API (one comment per MR, updated)."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import mr_comment  # noqa: E402

CI_ENV = {"CI_API_V4_URL": "https://gitlab.example/api/v4", "CI_PROJECT_ID": "42",
          "CI_PROJECT_URL": "https://gitlab.example/g/p", "CI_PIPELINE_ID": "100",
          "CI_PIPELINE_URL": "https://gitlab.example/g/p/-/pipelines/100",
          "CI_MERGE_REQUEST_IID": "7", "OSA_GITLAB_TOKEN": "secret"}


def report(**over) -> dict:
    base = {"failed": True, "blocking": 1, "would_block": 0, "existing": 2,
            "licenses": {"deny": 0}, "coverage_gaps": [],
            "gate_scope": {"scope": "new", "state": "compare", "baseline_ref": "main"},
            "findings": [
                {"id": "CVE-2", "severity": "high", "title": "lib | 1.0",
                 "location": "pkg:npm/lib@1.0", "status": "blocking"},
                {"id": "CVE-1", "severity": "critical", "title": "old",
                 "location": "pkg:npm/old@1", "status": "existing"}]}
    base.update(over)
    return base


class FakeGitLab:
    """Answers urlopen like the GitLab API, recording the writes."""

    def __init__(self, notes=(), jobs=()):
        self.notes, self.jobs, self.writes = list(notes), list(jobs), []

    def urlopen(self, request, timeout):
        path = request.full_url.split("/api/v4", 1)[1].split("?")[0]
        if request.get_method() == "GET":
            body = self.jobs if path.endswith("/jobs") else self.notes
            headers = {"X-Next-Page": ""}
        else:
            self.writes.append((request.get_method(), path, json.loads(request.data)))
            body, headers = {"id": 1}, {}
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps(body).encode()
        response.headers = headers
        return response


class BuildBodyTest(unittest.TestCase):
    def test_lists_only_the_blocking_findings_with_the_counts(self):
        body = mr_comment.build_body(report(), "", "https://dash", "https://pipe")
        self.assertTrue(body.startswith(mr_comment.marker("")))
        self.assertIn("pipeline blocked", body)
        self.assertIn("| 1 | 0 | 2 | 0 | 0 |", body)
        self.assertIn("`CVE-2`", body)
        self.assertNotIn("CVE-1", body)
        self.assertIn("lib \\| 1.0", body)  # a pipe would break the table
        self.assertIn("absent from `main`", body)
        self.assertIn("[📊 Dashboard](https://dash) · [Pipeline](https://pipe)", body)


class MainTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.report = Path(tmp.name, "security-report.json")
        self.report.write_text(json.dumps(report()), encoding="utf-8")

    def run_main(self, gitlab, env=CI_ENV, suffix=""):
        argv = ["mr_comment.py", "--report", str(self.report),
                "--dashboard-job", "osa_report_dashboard",
                # `=`: a suffix may start with a dash, as in the template.
                "--dashboard-path", "security-reports/dashboard.html", f"--suffix={suffix}"]
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.dict(os.environ, env, clear=True), \
                mock.patch("urllib.request.urlopen", gitlab.urlopen), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()):
            code = mr_comment.main()
        return code, out.getvalue()

    def test_first_pipeline_posts_a_comment_linking_the_dashboard(self):
        gitlab = FakeGitLab(jobs=[{"id": 55, "name": "osa_report_dashboard", "status": "success"}])
        code, _ = self.run_main(gitlab)
        self.assertEqual(code, 0)
        [(method, path, payload)] = gitlab.writes
        self.assertEqual((method, path), ("POST", "/projects/42/merge_requests/7/notes"))
        self.assertIn("https://gitlab.example/g/p/-/jobs/55/artifacts/file/"
                      "security-reports/dashboard.html", payload["body"])

    def test_next_pipeline_updates_the_same_comment(self):
        gitlab = FakeGitLab(notes=[{"id": 3, "body": "LGTM"},
                                   {"id": 9, "body": mr_comment.marker("") + "\nold"}])
        self.run_main(gitlab)
        [(method, path, _payload)] = gitlab.writes
        self.assertEqual((method, path), ("PUT", "/projects/42/merge_requests/7/notes/9"))

    def test_fork_merge_request_is_commented_on_the_target_project(self):
        gitlab = FakeGitLab()
        self.run_main(gitlab, env={**CI_ENV, "CI_MERGE_REQUEST_PROJECT_ID": "8"})
        self.assertEqual(gitlab.writes[0][1], "/projects/8/merge_requests/7/notes")

    def test_each_component_include_has_its_own_comment(self):
        gitlab = FakeGitLab(notes=[{"id": 9, "body": mr_comment.marker("") + "\nold"}])
        self.run_main(gitlab, suffix="-web")
        self.assertEqual(gitlab.writes[0][0], "POST")

    def test_without_token_or_merge_request_nothing_is_written(self):
        for drop in ("OSA_GITLAB_TOKEN", "CI_MERGE_REQUEST_IID"):
            with self.subTest(missing=drop):
                gitlab = FakeGitLab()
                env = {k: v for k, v in CI_ENV.items() if k != drop}
                code, _ = self.run_main(gitlab, env=env)
                self.assertEqual((code, gitlab.writes), (0, []))


if __name__ == "__main__":
    unittest.main()
