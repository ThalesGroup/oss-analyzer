# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""
Public advisory database links per finding ID, shared by the dashboard
(generate_dashboard.py) and the GitLab native reports (gitlab_reports.py)
so both point a given advisory at the same page.
"""
from __future__ import annotations

# Public advisory database URL per finding-ID prefix. Gitleaks/Semgrep rule
# IDs (e.g. "github-pat", "js.lang.security.audit...") have no public
# bulletin and are intentionally left unmapped — advisory_url() returns None
# for them, and the caller renders plain text instead of a link.
ADVISORY_URL_PATTERNS: list[tuple[str, str]] = [
    ("CVE-", "https://nvd.nist.gov/vuln/detail/{id}"),
    ("GHSA-", "https://github.com/advisories/{id}"),
    ("GO-", "https://pkg.go.dev/vuln/{id}"),
    ("PYSEC-", "https://osv.dev/vulnerability/{id}"),
    ("RUSTSEC-", "https://rustsec.org/advisories/{id}.html"),
]


def advisory_url(finding_id: str) -> str | None:
    for prefix, template in ADVISORY_URL_PATTERNS:
        if finding_id.startswith(prefix):
            return template.format(id=finding_id)
    return None
