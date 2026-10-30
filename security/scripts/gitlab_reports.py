#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""
Converts security-report.json (aggregate_report.py's output) into GitLab's
native report formats, shown in the MR's Reports tab:

    gl-dependency-scanning-report.json   -> "Security scan"  (Ultimate)
    gl-secret-detection-report.json      -> "Security scan"  (Ultimate)
    gl-code-quality-report.json          -> "Code Quality"   (every edition)

Built from the already normalized findings, not the raw scanner outputs:
dependencies are already deduplicated across Grype and OSV-Scanner, and
GitLab shows the same findings as the gate and the dashboard.

Code Quality only gets the findings that point at a line of the project's
own code (SAST, secrets, IaC) — not dependencies, which have none. On
Ultimate, a SAST/secret finding therefore shows in both Security scan and
Code Quality: accepted, so that editions without Ultimate still get a
native MR view.

All three files are always written, even empty: an empty report is what
tells GitLab that previously reported findings are gone.

Usage:
    python gitlab_reports.py --report security-reports/security-report.json \
                             --output-dir security-reports
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from advisories import advisory_url

# Declared schema version (gitlab-org/security-products/security-report-schemas).
# GitLab validates a report against the latest vendored patch of the declared
# MAJOR.MINOR, and rejects a report that doesn't validate — the pipeline then
# shows an error and the findings are dropped.
SCHEMA_VERSION = "15.2.1"

# Changing an analyzer/scanner ID makes GitLab treat every finding as a new
# vulnerability from a different scanner — keep them stable.
VENDOR = {"name": "oss-analyzer"}
ANALYZER = {"id": "oss-analyzer", "name": "oss-analyzer", "version": "1", "vendor": VENDOR}
SCANNERS = {
    "dependency_scanning": {"id": "oss-analyzer-sca", "name": "Grype + OSV-Scanner (oss-analyzer)",
                            "version": "1", "vendor": VENDOR},
    "secret_detection": {"id": "oss-analyzer-secrets", "name": "Gitleaks (oss-analyzer)",
                         "version": "1", "vendor": VENDOR},
}

GITLAB_SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium",
                   "low": "Low", "negligible": "Info", "unknown": "Unknown"}
# Code Climate severities; a finding that blocks the gate is a "blocker"
# whatever its own severity.
CODE_QUALITY_SEVERITY = {"critical": "critical", "high": "major", "medium": "minor",
                         "low": "info", "negligible": "info", "unknown": "info"}
CODE_QUALITY_CATEGORIES = ("sast", "secret", "iac")

# Identifier type per advisory-ID prefix; anything else gets a generic type.
IDENTIFIER_TYPES = [("CVE-", "cve"), ("GHSA-", "ghsa"), ("GO-", "go"),
                    ("PYSEC-", "pysec"), ("RUSTSEC-", "rustsec")]


def stable_id(*parts: str) -> str:
    """Same finding, same ID from one pipeline to the next."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "oss-analyzer:" + "|".join(parts)))


def split_location(location: str) -> tuple[str, int | None]:
    """'path/to/file.py:42' -> ('path/to/file.py', 42); no line -> (location, None);
    an empty line ('path/to/file.py:') -> ('path/to/file.py', None)."""
    path, sep, line = location.rpartition(":")
    if sep and line.isdigit():
        return path, int(line)
    if sep and not line and path:
        return path, None
    return location, None


def identifier(advisory_id: str) -> dict:
    kind = next((t for prefix, t in IDENTIFIER_TYPES if advisory_id.startswith(prefix)), "oss-analyzer")
    out = {"type": kind, "name": advisory_id, "value": advisory_id}
    url = advisory_url(advisory_id)
    if url:
        out["url"] = url
    return out


def status_note(f: dict) -> str:
    if f.get("status") == "exception":
        return "\n\nAccepted as an exception in policy-global.yml (oss-analyzer)."
    if f.get("status") == "blocking":
        return "\n\nBlocks the oss-analyzer gate."
    if f.get("status") == "would-block":
        return ("\n\nWould block the oss-analyzer gate in enforce mode (not enforced here: "
                "audit mode, or the new-findings-only gate outside a merge request).")
    if f.get("status") == "existing":
        return ("\n\nWould block the oss-analyzer gate, but already on the target branch: "
                "not brought by this merge request (new-findings-only gate).")
    return ""


def is_dependency_finding(f: dict) -> bool:
    # Trivy's container-image vulnerabilities share the "vuln" category but
    # aren't declared in a project manifest — out of dependency scanning.
    return f["category"] == "vuln" and bool({"grype", "osv"} & set(f["tool"].split("+")))


def dependency_vulnerability(f: dict) -> dict:
    package, _, version = f["title"].rpartition(" ")
    if not package:  # title without a version
        package, version = f["title"], ""
    manifest = f.get("file") or "sbom.cdx.json"
    vuln = {
        "id": stable_id("dependency_scanning", f["id"], f["location"]),
        "name": f"{f['id']} in {package}",
        "description": (f.get("description") or f"{f['id']} in {f['title']}") + status_note(f),
        "severity": GITLAB_SEVERITY[f["severity"]],
        "identifiers": [identifier(f["id"])]
                       + [identifier(a) for a in f.get("aliases", []) if a != f["id"]][:19],
        "location": {"file": manifest,
                     "dependency": {"package": {"name": package}, "version": version}},
    }
    if f.get("fixed"):
        vuln["solution"] = f"Upgrade {package} to {f['fixed']}."
    return vuln


def secret_vulnerability(f: dict) -> dict:
    path, line = split_location(f["location"])
    location = {"file": path,
                "commit": {"sha": f.get("commit") or os.environ.get("CI_COMMIT_SHA") or "unknown"}}
    if line:
        location.update(start_line=line, end_line=line)
    return {
        "id": stable_id("secret_detection", f["id"], f["location"]),
        "name": f["title"],
        "description": f"{f['title']} ({f['tool']} rule {f['id']})." + status_note(f),
        "severity": GITLAB_SEVERITY[f["severity"]],
        "identifiers": [{"type": f"{f['tool'].split('+')[0]}_rule_id",
                         "name": f"{f['tool'].split('+')[0]} rule {f['id']}", "value": f["id"]}],
        "location": location,
        "solution": "Revoke and rotate the secret, then remove it from the code "
                    "(and from the git history if needed).",
    }


def security_report(scan_type: str, vulnerabilities: list[dict], now: str) -> dict:
    return {
        "version": SCHEMA_VERSION,
        "scan": {"analyzer": ANALYZER, "scanner": SCANNERS[scan_type], "type": scan_type,
                 "start_time": now, "end_time": now, "status": "success"},
        "vulnerabilities": vulnerabilities,
    }


def code_quality_fingerprint(f: dict) -> str:
    """Stable across runs, distinct per finding: category, rule and location,
    plus — when the scanner gives them, i.e. for secrets — the commit and the
    columns, so that two secrets of one rule on one line, or one secret in
    two commits, don't share a fingerprint (GitLab would merge them). The
    other findings keep the fingerprint they always had."""
    key = f"{f['category']}|{f['id']}|{f['location']}"
    extra = f.get("extra") or {}
    parts = [str(v) for v in (f.get("commit"), extra.get("start_col"), extra.get("end_col"))
             if v not in (None, "")]
    if parts:
        key += "|" + "|".join(parts)
    return hashlib.md5(key.encode("utf-8")).hexdigest()


def code_quality_issue(f: dict) -> dict:
    path, line = split_location(f["location"])
    severity = "blocker" if f.get("status") == "blocking" else CODE_QUALITY_SEVERITY[f["severity"]]
    return {
        "type": "issue",
        "check_name": f["id"],
        "description": f"[{f['tool']}] {f['title']}",
        "categories": ["Security"],
        "severity": severity,
        "fingerprint": code_quality_fingerprint(f),
        "location": {"path": path, "lines": {"begin": line or 1}},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", required=True, type=Path,
                    help="security-report.json produced by aggregate_report.py")
    ap.add_argument("--output-dir", required=True, type=Path)
    args = ap.parse_args()

    findings = json.loads(args.report.read_text(encoding="utf-8")).get("findings", [])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    outputs = {
        "gl-dependency-scanning-report.json": security_report(
            "dependency_scanning",
            [dependency_vulnerability(f) for f in findings if is_dependency_finding(f)], now),
        "gl-secret-detection-report.json": security_report(
            "secret_detection",
            [secret_vulnerability(f) for f in findings if f["category"] == "secret"], now),
        "gl-code-quality-report.json": [
            code_quality_issue(f) for f in findings if f["category"] in CODE_QUALITY_CATEGORIES],
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in outputs.items():
        (args.output_dir / name).write_text(
            json.dumps(content, indent=2, ensure_ascii=False), encoding="utf-8")
        count = len(content if isinstance(content, list) else content["vulnerabilities"])
        print(f"{name}: {count} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
