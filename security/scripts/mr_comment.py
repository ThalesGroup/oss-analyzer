#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""
Posts the gate's summary as a comment on the merge request, from
security-report.json (aggregate_report.py's output): verdict, counts, the
blocking findings, and links to the dashboard and the pipeline.

One comment per merge request (per OSA_JOB_SUFFIX), found again by a hidden
marker and updated by every pipeline, instead of one more per push.

Needs a token allowed to write notes, which CI_JOB_TOKEN isn't: a project
access token (scope `api`, role Reporter) in the masked CI/CD variable
OSA_GITLAB_TOKEN. Without it, or outside a merge request pipeline, it warns
and does nothing (exit 0). An API error exits 1.

Usage (in the osa_report_mr_comment job):
    python mr_comment.py --report "$OSA_REPORT_DIR/security-report.json" \
        --dashboard-job "osa_report_dashboard" \
        --dashboard-path "$OSA_REPORT_DIR/dashboard.html" --suffix="$OSA_JOB_SUFFIX"
    (`--suffix=`: a suffix may start with a dash)
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

# Same severities and icons as security-report.md. Importing it also sets
# stdout/stderr to UTF-8 (emoji in the comment).
from aggregate_report import ICON, SEV_RANK

MAX_ROWS = 20


def marker(suffix: str) -> str:
    return f"<!-- oss-analyzer-mr-comment{suffix} -->"


def cell(text) -> str:
    """Table cell text: no pipe or newline breaking the Markdown table."""
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def findings_rows(findings: list[dict], status: str) -> list[dict]:
    rows = [f for f in findings if f.get("status") == status]
    return sorted(rows, key=lambda f: SEV_RANK.get(f.get("severity"), len(SEV_RANK)))


def build_body(report: dict, suffix: str, dashboard_url: str | None,
               pipeline_url: str | None) -> str:
    findings = [f for f in report.get("findings") or [] if isinstance(f, dict)]
    blocking = findings_rows(findings, "blocking")
    scope = report.get("gate_scope") or {}
    gaps = [g for g in report.get("coverage_gaps") or [] if g.get("blocking")]
    lic = report.get("licenses") or {}

    if report.get("failed"):
        title = "❌ oss-analyzer: pipeline blocked"
    elif report.get("would_block"):
        title = "⚠️ oss-analyzer: OK, not enforced — would block in enforce mode"
    else:
        title = "✅ oss-analyzer: OK"
    md = [marker(suffix), f"### {title}", ""]

    if scope.get("state") == "compare":
        md += [f"Only findings absent from `{scope.get('baseline_ref')}` block "
               "(new-findings-only gate).", ""]
    elif scope.get("state") == "full":
        md += [f"New-findings-only gate, but no report of `{scope.get('baseline_ref')}` "
               "to compare with: full gate.", ""]

    # Compared with the baseline: say how many license violations are new,
    # the total alone would count the backlog.
    new_lic = report.get("new_license_violations")
    denied = str(lic.get("deny", 0)) + (f" ({len(new_lic)} new)" if isinstance(new_lic, list)
                                        else "")
    md += ["| Blocking | Would block | Already on target | Denied licenses | Coverage gaps |",
           "|---|---|---|---|---|",
           f"| {report.get('blocking', 0)} | {report.get('would_block', 0)} | "
           f"{report.get('existing', 0)} | {denied} | {len(gaps)} |", ""]

    if blocking:
        md += [f"**Blocking findings** ({len(blocking)})", "",
               "| Sev. | Identifier | Subject | Location |", "|---|---|---|---|"]
        for f in blocking[:MAX_ROWS]:
            md.append(f"| {ICON.get(f.get('severity'), '❔')} | `{cell(f.get('id'))}` | "
                      f"{cell(f.get('title'))} | `{cell(f.get('location'))}` |")
        if len(blocking) > MAX_ROWS:
            md.append(f"| … | | _{len(blocking) - MAX_ROWS} more_ | |")
        md.append("")
    if new_lic:
        md += ["**License violations new to this merge request**: " + ", ".join(f"`{v}`" for v in new_lic[:10])
               + (f" and {len(new_lic) - 10} more" if len(new_lic) > 10 else ""), ""]
    if gaps:
        md += ["**Incomplete coverage**: " + ", ".join(
            f"{g.get('tool')} ({g.get('reason')})" for g in gaps), ""]

    links = []
    if dashboard_url:
        links.append(f"[📊 Dashboard]({dashboard_url})")
    if pipeline_url:
        links.append(f"[Pipeline]({pipeline_url})")
    if links:
        md += [" · ".join(links), ""]
    return "\n".join(md)


class GitLab:
    def __init__(self, api: str, token: str):
        self.api, self.token = api.rstrip("/"), token

    def call(self, method: str, path: str, payload: dict | None = None):
        """JSON body and the X-Next-Page header (pagination)."""
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            f"{self.api}{path}", data=data, method=method,
            headers={"PRIVATE-TOKEN": self.token, "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read() or b"null"), response.headers.get("X-Next-Page")

    def find(self, path: str, match) -> dict | None:
        page = "1"
        while page:
            sep = "&" if "?" in path else "?"
            items, page = self.call("GET", f"{path}{sep}per_page=100&page={page}")
            for item in items or []:
                if match(item):
                    return item
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", required=True, type=Path)
    ap.add_argument("--dashboard-job", default="",
                    help="Name of the job publishing the dashboard, for the link.")
    ap.add_argument("--dashboard-path", default="",
                    help="The dashboard's path in that job's artifacts.")
    ap.add_argument("--suffix", default="",
                    help="OSA_JOB_SUFFIX: one comment per component include.")
    args = ap.parse_args()

    env = os.environ
    mr_iid = env.get("CI_MERGE_REQUEST_IID")
    if not mr_iid:
        print("Not a merge request pipeline: no comment.")
        return 0
    token = env.get("OSA_GITLAB_TOKEN")
    if not token:
        print("::warning:: OSA_GITLAB_TOKEN isn't set: no MR comment. Add a project "
              "access token (scope api, role Reporter) as a masked CI/CD variable.")
        return 0
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"::warning:: {args.report} unreadable ({exc}): no MR comment.")
        return 0

    try:
        gitlab = GitLab(env["CI_API_V4_URL"], token)
        # The pipeline's project for its jobs; the merge request's own
        # project (the fork's target) for its notes.
        project = f"/projects/{urllib.parse.quote(env['CI_PROJECT_ID'], safe='')}"
        mr_project = env.get("CI_MERGE_REQUEST_PROJECT_ID") or env["CI_PROJECT_ID"]
        dashboard_url = None
        if args.dashboard_job and args.dashboard_path and env.get("CI_PIPELINE_ID"):
            job = gitlab.find(f"{project}/pipelines/{env['CI_PIPELINE_ID']}/jobs",
                              lambda j: j.get("name") == args.dashboard_job)
            if job and job.get("status") == "success":
                dashboard_url = (f"{env['CI_PROJECT_URL']}/-/jobs/{job['id']}/artifacts/file/"
                                 f"{args.dashboard_path.removeprefix('./')}")
        body = build_body(report, args.suffix, dashboard_url, env.get("CI_PIPELINE_URL"))
        notes = f"/projects/{urllib.parse.quote(mr_project, safe='')}/merge_requests/{mr_iid}/notes"
        note = gitlab.find(notes, lambda n: marker(args.suffix) in (n.get("body") or ""))
        if note:
            gitlab.call("PUT", f"{notes}/{note['id']}", {"body": body})
            print(f"MR comment updated (note {note['id']}).")
        else:
            gitlab.call("POST", notes, {"body": body})
            print("MR comment posted.")
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        print(f"::error:: MR comment failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
