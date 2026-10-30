# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""Tests of the `analyze` component template (templates/analyze.yml) itself:
the job graph, the artifacts each job reads from its `needs`, the SBOM
rules, and the arguments the aggregate job computes (--expect list,
new-findings-only baseline). Until now these were only exercised by real
pipelines."""
import copy
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "security" / "scripts"))

import aggregate_report  # noqa: E402

TEMPLATE = ROOT / "templates" / "analyze.yml"
SUFFIX = "$[[ inputs.OSA_JOB_SUFFIX ]]"
REPORT_DIR = "$[[ inputs.OSA_REPORT_DIR ]]/"

# What each job reads from OSA_REPORT_DIR (beyond the checkout): every file
# must come from a job in its `needs` (with artifacts) that publishes it.
READS = {
    "osa_sbom_merge": ["sbom.syft.cdx.json", "sbom.cdxgen.cdx.json"],
    "osa_sca_grype": ["sbom.cdx.json"],
    "osa_licenses_gate": [".osa/policy-global.yml", "sbom.cdx.json"],
    "osa_dtrack_upload": ["sbom.cdx.json"],
    "osa_sast_semgrep": [".osa/semgrep-packs.txt", ".osa/semgrep/policy-semgrep.yml"],
    "osa_secrets_gitleaks": [".osa/policy-gitleaks.toml"],
    "osa_report_aggregate": [".osa/policy-global.yml", "trivy-image.json", "reuse.json"]
                            + [f for f, _s, _sh in aggregate_report.EXPECTED_REPORTS.values()],
    "osa_report_dashboard": ["security-report.json"],
    "osa_report_gitlab_native": ["security-report.json"],
    "osa_report_mr_comment": ["security-report.json"],
    "osa_pages": ["dashboard.html"],
}
# Optional producers a file may also come from (the job that writes it may
# not run): sbom.cdx.json comes from osa_sbom_generate or osa_sbom_merge.


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) \
            else copy.deepcopy(v)
    return out


def load_template():
    spec, jobs = list(yaml.safe_load_all(TEMPLATE.read_text(encoding="utf-8")))

    def resolve(name, seen=()):
        job = jobs[name]
        parent = job.get("extends")
        if not parent:
            return job
        assert parent not in seen, f"extends loop at {name}"
        return deep_merge(resolve(parent, seen + (name,)), {k: v for k, v in job.items()
                                                            if k != "extends"})

    resolved = {name.replace(SUFFIX, ""): resolve(name) for name in jobs if name.startswith("osa_")}
    return spec["spec"], jobs, resolved


def needs_of(job: dict) -> list[dict]:
    """The job's `needs` within the component. osa_prepare's is the
    OSA_JOB_NEEDS input (the project's own jobs): not a list here."""
    needs = job.get("needs")
    if not isinstance(needs, list):
        return []
    out = []
    for n in needs:
        n = {"job": n} if isinstance(n, str) else dict(n)
        n["job"] = n["job"].replace(SUFFIX, "")
        out.append(n)
    return out


def published(job: dict) -> list[str]:
    return [p.replace(REPORT_DIR, "") for p in (job.get("artifacts") or {}).get("paths") or []]


def publishes(job: dict, filename: str) -> bool:
    return any(filename == p or (p.endswith("/") and filename.startswith(p)) for p in published(job))


class GraphTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec, cls.raw, cls.jobs = load_template()

    def test_every_job_and_need_carries_the_suffix(self):
        for name, job in self.raw.items():
            if name.startswith("osa_"):
                self.assertTrue(name.endswith(SUFFIX), name)
            for n in job.get("needs") or [] if isinstance(job.get("needs"), list) else []:
                target = n if isinstance(n, str) else n["job"]
                if target.startswith("osa_"):
                    self.assertTrue(target.endswith(SUFFIX), f"{name} → {target}")

    def test_every_need_is_a_job_of_the_component(self):
        for name, job in self.jobs.items():
            for n in needs_of(job):
                self.assertIn(n["job"], self.jobs, f"{name} needs an unknown job {n['job']}")

    def test_inputs_declared_are_used_and_used_are_declared(self):
        text = TEMPLATE.read_text(encoding="utf-8")
        used = set(re.findall(r"\$\[\[ inputs\.([A-Z_]+) \]\]", text))
        self.assertEqual(used, set(self.spec["inputs"]))
        self.assertTrue(all(i.startswith("OSA_") for i in self.spec["inputs"]))

    def test_infrastructure_failures_are_retried_not_script_failures(self):
        retry = self.raw[".osa_job"]["retry"]
        self.assertNotIn("script_failure", retry["when"])
        self.assertIn("runner_system_failure", retry["when"])


class ArtifactsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _spec, _raw, cls.jobs = load_template()

    def test_no_job_republishes_the_whole_report_folder(self):
        for name, job in self.jobs.items():
            self.assertNotIn("", published(job), f"{name} publishes the whole OSA_REPORT_DIR")

    def test_every_file_read_comes_from_a_needed_job(self):
        for reader, files in READS.items():
            producers = [self.jobs[n["job"]] for n in needs_of(self.jobs[reader])
                         if n.get("artifacts", True) is not False]
            for filename in files:
                with self.subTest(job=reader, file=filename):
                    self.assertTrue(any(publishes(p, filename) for p in producers),
                                    f"{reader} reads {filename}, published by none of its needs")

    def test_sbom_comes_from_generate_or_merge_never_both_required(self):
        for reader in ("osa_sca_grype", "osa_licenses_gate", "osa_dtrack_upload"):
            needs = {n["job"]: n for n in needs_of(self.jobs[reader])}
            self.assertIn("osa_sbom_generate", needs, reader)
            self.assertTrue(needs["osa_sbom_merge"].get("optional"), reader)


class SbomRulesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _spec, _raw, cls.jobs = load_template()

    def test_merge_runs_exactly_where_cdxgen_does(self):
        def rules(job):
            return [r for r in self.jobs[job]["rules"]]
        self.assertEqual(rules("osa_sbom_merge"), rules("osa_sbom_cdxgen"))

    def test_cdxgen_job_uses_no_interpreter_the_image_lacks(self):
        # A cdxgen image can be a standalone binary, without node or python:
        # a check relying on one failed there and dropped every valid SBOM
        #. Validation belongs to osa_sbom_merge.
        script = "\n".join(self.jobs["osa_sbom_cdxgen"]["script"])
        code = "\n".join(line.split("#", 1)[0] for line in script.splitlines())
        self.assertIsNone(re.search(r"\b(node|python3?|jq)\b", code), code)

    def test_generate_tests_the_same_manifests_as_the_exists_rule(self):
        exists = next(r["exists"] for r in self.jobs["osa_sbom_cdxgen"]["rules"] if "exists" in r)
        names = {p.split("/")[-1] for p in exists}
        script = "\n".join(self.jobs["osa_sbom_generate"]["script"])
        for name in names:
            self.assertIn(f"-name {name}", script)
        self.assertIn('"$OSA_SBOM"', script)  # Syft writes sbom.cdx.json when not merging


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class ExpectTest(unittest.TestCase):
    """Runs the aggregate job's script for real, with `python` replaced by a
    stand-in recording the arguments of each call (fetch_baseline.py,
    aggregate_report.py)."""

    @classmethod
    def setUpClass(cls):
        _spec, _raw, jobs = load_template()
        cls.script = "\n".join(jobs["osa_report_aggregate"]["script"])

    def calls(self, inputs: dict, files=(), env_extra=None) -> list[list[str]]:
        """Each `python` call of the script, as its argument list."""
        script = self.script
        for key, value in {"OSA_GATE_SCOPE": "all", **inputs}.items():
            script = script.replace(f"$[[ inputs.{key} ]]", value)
        with tempfile.TemporaryDirectory() as d:
            for f in files:
                Path(d, f).parent.mkdir(parents=True, exist_ok=True)
                Path(d, f).write_text("x", encoding="utf-8")
            stub = 'python() { printf "%s\\037" "$@" >> calls.out; echo >> calls.out; }\n'
            env = dict(os.environ, OSA_HOME="/opt", OSA_REPORT_DIR="r", OSA_CONFIG_DIR="r/.osa",
                       CI_JOB_NAME="osa_report_aggregate")
            env.pop("CI_MERGE_REQUEST_IID", None)  # not a merge request unless env_extra says so
            env.update(env_extra or {})
            subprocess.run(["bash", "-c", "set -eo pipefail\n" + stub + script],
                           cwd=d, env=env, check=True, capture_output=True)
            lines = Path(d, "calls.out").read_text(encoding="utf-8").splitlines()
            return [line.rstrip("\x1f").split("\x1f") for line in lines if line]

    def expect(self, inputs: dict, files=()) -> str:
        args = self.calls(inputs, files)[-1]
        return args[args.index("--expect") + 1]

    ALL_ON = {"OSA_ENABLE_SCA_OSV": "true", "OSA_ENABLE_SAST_SEMGREP": "true",
              "OSA_ENABLE_SECRETS_GITLEAKS": "true", "OSA_ENABLE_CONTAINERS_TRIVY": "true"}

    def test_default_without_dockerfile(self):
        self.assertEqual(self.expect(self.ALL_ON), "grype,licenses,osv,semgrep,gitleaks")

    def test_dockerfile_adds_trivy(self):
        self.assertEqual(self.expect(self.ALL_ON, ["sub/Dockerfile"]),
                         "grype,licenses,osv,semgrep,gitleaks,trivy")

    def test_disabled_scanners_are_not_expected(self):
        off = {k: "false" for k in self.ALL_ON}
        self.assertEqual(self.expect(off, ["Dockerfile"]), "grype,licenses")

    def test_every_expected_name_is_known_to_the_aggregation(self):
        names = self.expect(self.ALL_ON, ["Dockerfile"]).split(",")
        self.assertTrue(set(names) <= set(aggregate_report.EXPECTED_REPORTS), names)

    MR = {"CI_MERGE_REQUEST_IID": "7", "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main"}

    def test_baseline_fetched_only_with_scope_new_on_a_merge_request(self):
        for scope, env in (("all", self.MR), ("new", None)):
            with self.subTest(scope=scope, merge_request=bool(env)):
                [call] = self.calls({**self.ALL_ON, "OSA_GATE_SCOPE": scope}, env_extra=env)
                self.assertEqual(call[call.index("--gate-scope") + 1], scope)
                self.assertNotIn("--merge-request", call)

    def test_scope_new_on_a_merge_request_compares_with_the_target_branch(self):
        fetch, aggregate = self.calls({**self.ALL_ON, "OSA_GATE_SCOPE": "new"},
                                      env_extra=self.MR)
        self.assertTrue(fetch[0].endswith("fetch_baseline.py"))
        self.assertEqual(fetch[fetch.index("--ref") + 1], "main")
        self.assertEqual(fetch[fetch.index("--job") + 1], "osa_report_aggregate")
        self.assertEqual(fetch[fetch.index("--path") + 1], "r/security-report.json")
        baseline = fetch[fetch.index("--output") + 1]
        self.assertIn("--merge-request", aggregate)
        self.assertEqual(aggregate[aggregate.index("--baseline") + 1], baseline)
        self.assertEqual(aggregate[aggregate.index("--gate-scope") + 1], "new")


if __name__ == "__main__":
    unittest.main()
