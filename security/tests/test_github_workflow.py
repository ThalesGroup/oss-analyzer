# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""Tests of the GitHub reusable workflow (.github/workflows/security.yml):
called from another repository, its jobs must bring oss-analyzer's scripts
and resolved settings themselves, since the caller has neither."""
import unittest
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "security.yml"


def load():
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # PyYAML reads the `on:` key as True (YAML 1.1 boolean).
    return doc.get("on", doc.get(True)), doc["jobs"]


def runs(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in job.get("steps", []))


def needs(job: dict) -> list:
    n = job.get("needs") or []
    return [n] if isinstance(n, str) else n


class ReusableWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.on, cls.jobs = load()

    def test_oss_analyzer_location_is_an_input(self):
        inputs = self.on["workflow_call"]["inputs"]
        for name in ("oss-analyzer-repository", "oss-analyzer-ref", "settings-dir"):
            self.assertIn(name, inputs)

    def test_jobs_running_scripts_check_out_oss_analyzer(self):
        for name, job in self.jobs.items():
            if "$OSA_HOME" not in runs(job):
                continue
            with self.subTest(job=name):
                checkouts = [s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout")
                             and (s.get("with") or {}).get("path") == ".oss-analyzer"]
                self.assertEqual(len(checkouts), 1, f"{name} runs oss-analyzer's scripts without its checkout")
                self.assertIn("inputs.oss-analyzer-repository", checkouts[0]["with"]["repository"])
                self.assertIn("inputs.oss-analyzer-ref", checkouts[0]["with"]["ref"])
                # A private oss-analyzer is not readable with the caller's
                # GITHUB_TOKEN: the optional secret must reach every checkout,
                # without staying in .git/config for the scripts' steps.
                self.assertIn("secrets.OSS_ANALYZER_TOKEN", checkouts[0]["with"]["token"])
                self.assertIs(checkouts[0]["with"]["persist-credentials"], False)

    def test_project_searches_skip_the_oss_analyzer_checkout(self):
        # report-aggregate once found oss-analyzer's own Dockerfile under
        # .oss-analyzer and expected a Trivy report the caller never had.
        for name, job in self.jobs.items():
            if "$OSA_HOME" not in runs(job):
                continue
            for line in runs(job).splitlines():
                if "find ." in line:
                    with self.subTest(job=name, line=line.strip()):
                        self.assertIn('-path "./$OSA_HOME" -prune', line)

    def test_oss_analyzer_token_is_an_optional_secret(self):
        secrets = self.on["workflow_call"]["secrets"]
        self.assertIs(secrets["OSS_ANALYZER_TOKEN"]["required"], False)

    def test_no_job_runs_scripts_from_the_callers_checkout(self):
        for name, job in self.jobs.items():
            self.assertNotIn("python security/scripts/", runs(job), name)

    def test_jobs_reading_settings_get_them_from_prepare(self):
        for name, job in self.jobs.items():
            if name == "prepare" or "$OSA_CONFIG_DIR" not in runs(job):
                continue
            with self.subTest(job=name):
                self.assertIn("prepare", needs(job))
                downloads = [s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/download-artifact")
                             and (s.get("with") or {}).get("name") == "osa-settings"]
                self.assertEqual(len(downloads), 1, f"{name} reads $OSA_CONFIG_DIR without osa-settings")

    def test_prepare_publishes_the_hidden_settings_folder(self):
        upload = next(s for s in self.jobs["prepare"]["steps"]
                      if str(s.get("uses", "")).startswith("actions/upload-artifact"))
        self.assertEqual(upload["with"]["name"], "osa-settings")
        self.assertTrue(upload["with"]["include-hidden-files"])  # .osa is hidden
        self.assertIn("prepare_settings.py", runs(self.jobs["prepare"]))


if __name__ == "__main__":
    unittest.main()
