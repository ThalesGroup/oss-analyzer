#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""
Downloads the target branch's latest security-report.json: the baseline of
the new-findings-only gate (OSA_GATE_SCOPE: new) on a merge request pipeline,
read by aggregate_report.py --baseline.

Uses GitLab's "single artifact file from a branch" API with the job's own
CI_JOB_TOKEN (no extra token: same project), on the merge request's target
project (CI_MERGE_REQUEST_PROJECT_ID, else CI_PROJECT_ID):

    GET $CI_API_V4_URL/projects/<project>/jobs/artifacts/<ref>/raw/<path>?job=<job>

GitLab serves it from the ref's latest successful pipeline. Never fails:
without a baseline (no successful pipeline yet, artifacts expired, API
error) nothing is written, and aggregate_report.py applies the full gate.

Usage (in the osa_report_aggregate job):
    python fetch_baseline.py --ref "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" \
        --job "$CI_JOB_NAME" --path "$OSA_REPORT_DIR/security-report.json" \
        --output "$OSA_REPORT_DIR/baseline/security-report.json"
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Drops the JOB-TOKEN header when a redirect leaves GitLab's host:
    with artifacts in object storage, GitLab redirects to a presigned URL,
    and urllib would otherwise send the token along to that third party."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).netloc != \
                urllib.parse.urlsplit(req.full_url).netloc:
            new.remove_header("Job-token")
        return new


def baseline_url(api: str, project: str, ref: str, path: str, job: str) -> str:
    return (f"{api.rstrip('/')}/projects/{urllib.parse.quote(project, safe='')}"
            f"/jobs/artifacts/{urllib.parse.quote(ref, safe='')}"
            f"/raw/{urllib.parse.quote(path.removeprefix('./'), safe='/')}"
            f"?job={urllib.parse.quote(job, safe='')}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ref", required=True, help="Branch holding the baseline.")
    ap.add_argument("--job", required=True, help="Job whose artifact it is.")
    ap.add_argument("--path", required=True, help="The artifact's path in that job.")
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()

    # The merge request's target project: not the pipeline's own project
    # when it runs in a fork.
    env = os.environ
    api = env.get("CI_API_V4_URL")
    project = env.get("CI_MERGE_REQUEST_PROJECT_ID") or env.get("CI_PROJECT_ID")
    token = env.get("CI_JOB_TOKEN")
    if not (api and project and token):
        print("::warning:: CI_API_V4_URL, CI_PROJECT_ID or CI_JOB_TOKEN missing: "
              "no baseline.")
        return 0
    url = baseline_url(api, project, args.ref, args.path, args.job)
    request = urllib.request.Request(url, headers={"JOB-TOKEN": token})
    opener = urllib.request.build_opener(SameHostRedirects)
    try:
        with opener.open(request, timeout=60) as response:
            body = response.read()
        json.loads(body)
    except urllib.error.HTTPError as exc:
        # 404: no successful pipeline on that ref with this job, or expired.
        print(f"::warning:: No baseline from {args.ref} ({args.job}): HTTP {exc.code}.")
        return 0
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"::warning:: No baseline from {args.ref} ({args.job}): {exc}.")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(body)
    print(f"Baseline: {args.path} of {args.job}, latest successful pipeline of {args.ref}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
