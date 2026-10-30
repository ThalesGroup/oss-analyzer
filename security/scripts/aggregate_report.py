#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""
Aggregates scanner outputs into a single report and applies the policy.

Reads whatever it finds in --input-dir (every file is optional):
    grype.json  osv.json  semgrep.json  gitleaks.json
    trivy-image.json  trivy-iac.json  licenses.json  reuse.json
    coverage.json  (steps that degraded or produced nothing — written by
                    analyze-archive.sh; absent means coverage wasn't tracked)

--expect names the scanners that were supposed to run (CI sets it from the
jobs it enabled). A missing, empty or unreadable report from one of them is
a coverage gap, and the verdict must not read "OK" on a scan that did not
happen: in enforce mode (of the policy section the scanner feeds) the gap
blocks like a finding; in audit mode it only warns.

--gate-scope new blocks only what a merge request brings (onboarding of a
project with a backlog). With --merge-request and --baseline (the target
branch's latest security-report.json, fetched by fetch_baseline.py), a
finding or a license violation already in the baseline is reported as
"existing" and doesn't block (secrets excepted: see compare_key). On a
merge request without a usable baseline, the gate stays complete (every
finding counts as new). Outside a merge request, nothing to compare with:
findings and licenses are reported without blocking, as in audit mode — so
a project without merge request pipelines gets no blocking gate at all.
Coverage gaps block in every case.

Produces security-report.md + security-report.json, and exits with code 1 if
the policy defined in policy-global.yml is violated.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

# Always output UTF-8: the report contains emoji (✅⚠️⛔), and a Windows
# terminal in cp1252 would otherwise crash on a bare print().
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

from policy import effective_policy  # noqa: E402 (after the stream setup)

# Finding category -> policy section carrying its mode (enforce | audit).
CATEGORY_MODE_SECTION = {"vuln": "vulnerabilities", "sast": "sast",
                         "iac": "sast", "secret": "secrets"}

# Scanner (--expect name) -> (its report, policy section whose mode decides
# whether a missing report blocks, what the report is: the key its JSON
# object always has, or `list` for a JSON array). The shape is what tells a
# real scan with no finding (`{"matches": []}`) from an error document or a
# placeholder (`{}`, `null`) a failed scanner may leave.
EXPECTED_REPORTS = {
    "grype": ("grype.json", "vulnerabilities", "matches"),
    "osv": ("osv.json", "vulnerabilities", "results"),
    "semgrep": ("semgrep.json", "sast", "results"),
    "gitleaks": ("gitleaks.json", "secrets", "list"),
    "licenses": ("licenses.json", "licenses", "summary"),
    # Trivy's IaC scan (trivy config): misconfigurations count as SAST.
    "trivy": ("trivy-iac.json", "sast", "SchemaVersion"),
}

SEVERITIES = ["critical", "high", "medium", "low", "negligible", "unknown"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡",
        "low": "🔵", "negligible": "⚪", "unknown": "❔"}


def load(path: Path) -> Any | None:
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"::warning:: {path.name} unreadable ({exc}) — skipped.")
        return None


def report_problem(path: Path, shape: str | None = None) -> str | None:
    """Why a scanner's report can't be used (None when it is fine): missing,
    empty, not JSON, or — given its `shape` (EXPECTED_REPORTS) — not that
    scanner's report. A scan with no finding still has that shape
    (`{"results": []}`, `[]`); an error document or a placeholder doesn't."""
    if not path.exists():
        return "report not produced"
    if path.stat().st_size == 0:
        return "report empty"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "report unreadable"
    if shape == "list" and not isinstance(data, list):
        return "not a scan report (expected a JSON array)"
    if shape and shape != "list" and not (isinstance(data, dict) and shape in data):
        return f"not a scan report (no `{shape}` key)"
    return None


def expected_gaps(input_dir: Path, expected: list[str], policy: dict) -> list[dict]:
    """Coverage gaps for the expected scanners whose report can't be used.
    `blocking` is false when the scanner's category is in audit mode."""
    gaps = []
    for tool in expected:
        filename, section, shape = EXPECTED_REPORTS[tool]
        reason = report_problem(input_dir / filename, shape)
        if reason:
            audit = (policy.get(section) or {}).get("mode") == "audit"
            gaps.append({"tool": tool, "reason": reason, "blocking": not audit})
    return gaps


def compare_key(f: dict) -> tuple | None:
    """Identity of a finding across two pipelines (--gate-scope new), or
    None for a finding never matched with the baseline. The line number is
    dropped from SAST locations (`path:line`): a line moved by an unrelated
    edit must not turn an old finding into a new one. Secrets are never
    matched: on a merge request Gitleaks only scans its commits, so a
    secret found there is new, and matching by file would let a rotated
    credential pass for the old one."""
    if f.get("category") == "secret":
        return None
    location = str(f.get("location", ""))
    if f.get("category") == "vuln":
        # A baseline written before purls were normalized still matches.
        location = normalize_purl(location)
    if f.get("category") == "sast":
        path, sep, line = location.rpartition(":")
        if sep and (line.isdigit() or not line):
            location = path
    return (f.get("category"), f.get("id"), location)


def component_key(c: dict) -> str:
    """A component without its version: its purl stripped of version and
    qualifiers, else its name. A version bump doesn't change a license, so
    it doesn't make a license violation new."""
    purl = str(c.get("purl") or "").split("?", 1)[0].split("#", 1)[0]
    if purl:
        head, sep, _version = purl.rpartition("@")
        return head if sep and "/" in head else purl
    return str(c.get("name", "?"))


def license_violations(lic: dict, lic_pol: dict) -> list[str]:
    """Components whose license verdict fails the license gate (exceptions
    already applied by license_gate.py), by component_key."""
    failing = set()
    if lic_pol.get("fail_on_deny", True):
        failing.add("deny")
    if lic_pol.get("fail_on_review", False):
        failing.add("review")
    return sorted({component_key(c) for c in lic.get("components", []) or []
                   if isinstance(c, dict) and c.get("verdict") in failing})


def license_components(lic: dict) -> list[dict]:
    """The components whose license the gate didn't allow (verdict review or
    deny; an exempted one is already allow), for the dashboard's Licenses
    tab: name, version, purl, licenses found (empty: none) and verdict."""
    keep = ("name", "version", "purl", "licenses", "verdict")
    return [{k: c.get(k) for k in keep} for c in lic.get("components", []) or []
            if isinstance(c, dict) and c.get("verdict") in ("review", "deny")]


def load_baseline(path: Path | None) -> dict | None:
    """The target branch's security-report.json, or None when it's missing
    or isn't one (no `findings` list)."""
    data = load(path) if path else None
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return data
    return None


def normalize_purl(purl: str) -> str:
    """A dependency's purl as one component identity, whoever reported it:
    without qualifiers or subpath (the `?type=jar` an SBOM entry from cdxgen
    adds to the same Maven artifact) and percent-decoded (Grype's
    `v3.2.0%2Bincompatible` is OSV's `v3.2.0+incompatible`, its
    `%40scope/name` OSV's `@scope/name`). Anything else is kept as-is."""
    if not purl.startswith("pkg:"):
        return purl
    return unquote(purl.split("#", 1)[0].split("?", 1)[0])


def sev(value: Any) -> str:
    s = str(value or "unknown").strip().lower()
    return s if s in SEV_RANK else "unknown"


def finding(tool, ident, severity, title, location, fixed=None, category="vuln", extra=None,
            file=None, description=None, aliases=None, commit=None):
    """`file`, `description`, `aliases` and `commit` are optional details,
    only kept when the scanner provides them: not used by the gate itself,
    but required by GitLab's native report formats (gitlab_reports.py) —
    `file` is the manifest/lock file a dependency is declared in (`location`
    stays the normalized purl, for deduplication), `aliases` the other IDs of the same
    advisory (CVE for a GHSA, ...), `commit` the commit a secret was found in."""
    out = {"tool": tool, "id": ident, "severity": sev(severity), "title": title,
           "location": location, "fixed": fixed, "category": category}
    for key, value in (("file", file), ("description", description),
                       ("aliases", aliases), ("commit", commit)):
        if value:
            out[key] = value
    if extra:
        out["extra"] = extra
    return out


# --------------------------------------------------------------------------- #
#  Parsers — each one tolerates a missing or partial format
# --------------------------------------------------------------------------- #
def parse_grype(data) -> list[dict]:
    out = []
    for m in (data or {}).get("matches", []):
        v = m.get("vulnerability", {})
        a = m.get("artifact", {})
        fix = (v.get("fix") or {}).get("state")
        versions = (v.get("fix") or {}).get("versions") or []
        locations = a.get("locations") or [{}]
        out.append(finding(
            "grype", v.get("id", "?"), v.get("severity"),
            f"{a.get('name', '?')} {a.get('version', '')}".strip(),
            normalize_purl(a.get("purl", "")),
            fixed=", ".join(versions) if fix == "fixed" else None,
            file=locations[0].get("path"),
            description=v.get("description"),
            aliases=[r["id"] for r in m.get("relatedVulnerabilities", []) if r.get("id")]))
    return out


# OSV ecosystems mapped to the corresponding purl type prefix (best-effort;
# unlike Grype, OSV-Scanner's JSON doesn't provide a ready-made purl).
OSV_ECOSYSTEM_PURL_TYPE = {
    "go": "golang", "npm": "npm", "pypi": "pypi", "maven": "maven",
    "cargo": "cargo", "nuget": "nuget", "rubygems": "gem", "packagist": "composer",
}


def osv_purl(name: str, version: str, ecosystem: str) -> str:
    """Reconstructs a purl from the OSV-Scanner format, normalized to match
    what Grype produces for the same component — otherwise the same
    package seen by both scanners ends up with two different `location`
    values, which breaks cross-scanner deduplication and per-component
    grouping in the dashboard.

      - Maven: OSV gives "groupId:artifactId"; Grype/purl expects
        "groupId/artifactId" as namespace/name.
      - Go: OSV omits the "v" prefix on pseudo-versions; Grype keeps it.
    Then normalize_purl(), as for Grype's purls.
    """
    purl_type = OSV_ECOSYSTEM_PURL_TYPE.get(ecosystem, ecosystem or "generic")
    if purl_type == "maven" and ":" in name:
        group_id, _, artifact_id = name.partition(":")
        name = f"{group_id}/{artifact_id}"
    if purl_type == "golang" and version and not version.startswith("v"):
        version = f"v{version}"
    return normalize_purl(f"pkg:{purl_type}/{name}@{version}")


def osv_fixed_version(vuln: dict) -> str | None:
    """Extracts the first fixed version found in
    affected[].ranges[].events[].fixed. Without this extraction, ignore_unfixed
    (enabled by default in policy-global.yml) would wrongly classify any vulnerability
    reported only by OSV-Scanner as "unfixed" — even when a fix genuinely
    exists — and would therefore exclude it from blocking."""
    for aff in vuln.get("affected", []) or []:
        for r in aff.get("ranges", []) or []:
            for event in r.get("events", []) or []:
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return None


def parse_osv(data) -> list[dict]:
    out = []
    for res in (data or {}).get("results", []):
        source = (res.get("source") or {}).get("path", "")
        for pkg in res.get("packages", []):
            info = pkg.get("package", {})
            name = info.get("name", "?")
            version = info.get("version", "")
            ecosystem = str(info.get("ecosystem", "")).lower()
            # Same convention as parse_grype: location = component
            # identifier (purl type), not the manifest file — needed for
            # cross-scanner deduplication and per-component grouping in
            # the dashboard to work across both tools.
            location = osv_purl(name, version, ecosystem) if name != "?" else source
            for v in pkg.get("vulnerabilities", []):
                db = v.get("database_specific") or {}
                out.append(finding(
                    "osv", v.get("id", "?"), db.get("severity"),
                    f"{name} {version}".strip(),
                    location, fixed=osv_fixed_version(v),
                    file=source,
                    description=v.get("summary") or (v.get("details") or "").split("\n")[0],
                    aliases=v.get("aliases")))
    return out


SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def short_title(text: str, limit: int = 160) -> str:
    """The first line of `text`, cut at a word boundary past `limit`
    characters, with an ellipsis."""
    first = text.strip().split("\n")[0]
    if len(first) <= limit:
        return first
    cut = first[:limit].rsplit(" ", 1)[0] or first[:limit]
    return cut.rstrip(" ,.;:") + "…"


def parse_semgrep(data) -> list[dict]:
    """The rule's message is the title, shortened (short_title); the whole
    message is kept as the description."""
    out = []
    for r in (data or {}).get("results", []):
        extra = r.get("extra", {})
        line = (r.get("start") or {}).get("line", "")
        message = (extra.get("message") or "").strip()
        out.append(finding(
            "semgrep", r.get("check_id", "?"),
            SEMGREP_SEV.get(str(extra.get("severity")).upper(), "medium"),
            short_title(message),
            f"{r.get('path', '?')}:{line}", category="sast",
            description=message if short_title(message) != message else None))
    return out


def parse_gitleaks(data) -> list[dict]:
    out = []
    for r in data or []:
        out.append(finding(
            "gitleaks", r.get("RuleID", "?"), "critical",
            r.get("Description", "Secret detected"),
            f"{r.get('File', '?')}:{r.get('StartLine', '')}",
            category="secret", commit=r.get("Commit"),
            # Exact secret columns on its line: needed to redact precisely
            # if generate_dashboard.py embeds a context excerpt around the
            # line (Gitleaks' Match is already redacted, but doesn't
            # contain the neighboring lines).
            extra={"start_line": r.get("StartLine"), "end_line": r.get("EndLine"),
                   "start_col": r.get("StartColumn"), "end_col": r.get("EndColumn")}))
    return out


def redact_line(line: str, start_col: int | None, end_col: int | None) -> str:
    """Replaces the [start_col, end_col) portion (1-indexed, as reported
    by Gitleaks) with ███, keeping the rest of the line readable for
    context. Without valid columns, redacts the entire line out of
    caution — better to over-redact than to leak a secret through an
    incorrect position."""
    if not start_col or not end_col or start_col < 1 or end_col <= start_col:
        return "█" * min(len(line), 40) if line.strip() else line
    i, j = start_col - 1, min(end_col - 1, len(line))
    return line[:i] + "█" * max(j - i, 3) + line[j:]


def project_relative(path: str, source_dir: Path | None) -> str:
    """A scanner-reported file path, relative to the scanned project root.
    OSV-Scanner reports absolute paths (/builds/<group>/<project>/poetry.lock
    in CI), Grype root-anchored ones (/poetry.lock), and the Docker fallback
    of analyze-archive.sh mounts the project under /src. That /src/ prefix
    is only dropped when the file really sits at the project root without
    it — a genuine src/ folder (src/frontend/package.json) stays as is."""
    if source_dir is not None:
        root = source_dir.as_posix().rstrip("/") + "/"
        if path.startswith(root):
            return path[len(root):]
    rel = path.lstrip("/")
    if (source_dir is not None and rel.startswith("src/")
            and not (source_dir / rel).exists() and (source_dir / rel[len("src/"):]).exists()):
        return rel[len("src/"):]
    return rel


def secret_context(source_dir: Path | None, location: str, extra: dict) -> dict | None:
    """Reads ONLY the line of the detected secret (never neighboring
    lines), redacted by column position. Deliberately without context
    lines before/after: a neighboring line might contain another secret
    that Gitleaks didn't detect (a rule that doesn't cover it, a false
    negative) — showing it in clear text via a different finding's
    context window would be a leak. Redaction always uses the column
    position reported by the tool, never by interpreting the line's
    text. Returns None if the file isn't accessible or if the metadata
    is insufficient — the caller should then skip embedding a preview
    rather than producing an incorrect one (and therefore potentially
    unredacted)."""
    if source_dir is None:
        return None
    path_part, _, _ = location.rpartition(":")
    if not path_part:
        return None
    start_line = extra.get("start_line")
    if not isinstance(start_line, int) or start_line < 1:
        return None

    # location is the path as seen by the tool inside its container/scan
    # root (often prefixed /src/ or absolute); we only keep the part
    # relative to the source project root to resolve it under source_dir.
    rel = path_part.lstrip("/")
    if rel.startswith("src/"):
        rel = rel[len("src/"):]
    candidate = (source_dir / rel).resolve()
    try:
        candidate.relative_to(source_dir.resolve())
    except ValueError:
        return None  # outside the expected source folder — read nothing
    if not candidate.is_file():
        return None

    try:
        lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    end_line = extra.get("end_line") or start_line
    if start_line > len(lines):
        return None

    out_lines = []
    for n in range(start_line, min(end_line, len(lines)) + 1):
        text = redact_line(lines[n - 1], extra.get("start_col"), extra.get("end_col"))
        out_lines.append({"number": n, "text": text, "highlight": True})
    return {"lines": out_lines, "path": rel}


def parse_trivy(data, category="vuln") -> list[dict]:
    out = []
    for res in (data or {}).get("Results", []):
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            out.append(finding(
                "trivy", v.get("VulnerabilityID", "?"), v.get("Severity"),
                f"{v.get('PkgName', '?')} {v.get('InstalledVersion', '')}".strip(),
                target, fixed=v.get("FixedVersion") or None))
        for m in res.get("Misconfigurations", []) or []:
            out.append(finding(
                "trivy", m.get("ID", "?"), m.get("Severity"),
                m.get("Title", ""), target, category="iac"))
        for s in res.get("Secrets", []) or []:
            out.append(finding(
                "trivy", s.get("RuleID", "?"), "critical",
                s.get("Title", "Secret detected"),
                f"{target}:{s.get('StartLine', '')}", category="secret"))
    return out


# REUSE (https://reuse.software/) reasons, in the order they should be
# listed when a file hits more than one. unused_licenses is deliberately
# NOT here: it flags a leftover file under LICENSES/ with no source file
# pointing at it — a cleanup of that directory, not a non-compliant source
# file — so it's reported as a separate count rather than a per-file finding.
REUSE_REASON_KEYS = [
    ("missing_copyright_info", "missing copyright"),
    ("missing_licensing_info", "missing SPDX license identifier"),
    ("bad_licenses", "invalid license identifier"),
    ("deprecated_licenses", "deprecated license identifier"),
    ("missing_licenses", "referenced license text absent from LICENSES/"),
    ("licenses_without_extension", "license file missing .txt extension"),
    ("read_errors", "file unreadable"),
]


def parse_reuse(data) -> list[dict]:
    """Always non-blocking, by design (see policy-global.yml): this is a
    sensitization signal for whatever project this pipeline scans — most
    won't have adopted the REUSE spec (SPDX-License-Identifier/copyright
    headers) — not a compliance gate. Every finding here is therefore
    fixed severity "low" — reporting only, regardless of policy-global.yml."""
    out = []
    nc = (data or {}).get("non_compliant", {}) or {}
    # A file can appear under several reasons at once (e.g. both missing
    # copyright and missing license id) — one finding per file, with the
    # reasons merged, rather than one finding per (file, reason) pair.
    reasons: dict[str, list[str]] = {}
    for key, label in REUSE_REASON_KEYS:
        for path in nc.get(key, []) or []:
            reasons.setdefault(path, []).append(label)

    # reuse lint reports paths as seen under --root (e.g. "/data/…" when
    # run with --root /data); keep only the part relative to the scanned
    # project so it matches how every other tool reports `location`.
    for path, why in reasons.items():
        out.append(finding(
            "reuse", "REUSE", "low", "; ".join(why),
            path.lstrip("/"), category="license_header"))
    return out


def merge_findings(prev: dict, f: dict) -> dict:
    """One finding out of two duplicates: the most severe one (on equal
    severity, the later one), completed with what only the other has —
    every scanner name, `fixed`, `file`, `description`, `commit`, and every
    identifier as aliases (the other scanner's ID included)."""
    winner = f if SEV_RANK[f["severity"]] <= SEV_RANK[prev["severity"]] else prev
    loser = prev if winner is f else f
    tools = prev["tool"].split("+") + [t for t in f["tool"].split("+")
                                       if t not in prev["tool"].split("+")]
    winner["tool"] = "+".join(tools)
    for detail in ("fixed", "file", "description", "commit"):
        if not winner.get(detail) and loser.get(detail):
            winner[detail] = loser[detail]
    aliases = (set(winner.get("aliases", [])) | set(loser.get("aliases", []))
               | {loser["id"]}) - {winner["id"]}
    if aliases:
        winner["aliases"] = sorted(aliases)
    return winner


def deduplicate(findings: list[dict]) -> list[dict]:
    """Merges the findings that are one problem reported twice (merge_findings),
    most severe first in the result.

    A dependency vulnerability is one per component and advisory: same
    `location` (a purl normalized by the parsers, so the SBOM's two entries
    of one artifact, and Grype's and OSV's copies, share it) and an ID or an
    alias in common — titles differ between scanners (`jackson-databind
    2.9.8` vs `com.fasterxml.jackson.core:jackson-databind 2.9.8`), and so
    do IDs (Grype's GHSA, OSV's PYSEC aliasing it). A vulnerability whose
    location isn't a purl (Trivy's image scan: the image) is told apart by
    its title too, the package. Anything else is one per category, ID,
    title and location."""
    merged: list[dict] = []
    by_component: dict[tuple, list[tuple[set, dict]]] = {}
    by_key: dict[tuple, dict] = {}
    for f in findings:
        if f["category"] == "vuln":
            ids = {f["id"], *f.get("aliases", [])}
            component = ((f["location"],) if str(f["location"]).startswith("pkg:")
                         else (f["location"], f["title"]))
            bucket = by_component.setdefault(component, [])
            # The new finding may bridge several entries (one aliasing its
            # ID, another one of its aliases): they all become one.
            for entry in [e for e in bucket if e[0] & ids]:
                bucket.remove(entry)
                ids |= entry[0]
                f = merge_findings(entry[1], f)
            bucket.append((ids, f))
            continue
        key = (f["category"], f["id"], f["title"], f["location"])
        by_key[key] = merge_findings(by_key[key], f) if key in by_key else f
    for bucket in by_component.values():
        merged += [f for _ids, f in bucket]
    merged += by_key.values()
    return sorted(merged, key=lambda f: (SEV_RANK[f["severity"]], f["category"],
                                         str(f["location"]), str(f["id"])))


def findings_table(rows: list[dict], limit: int = 100) -> list[str]:
    """Markdown table of findings, most severe first, capped at `limit`."""
    md = ["| Sev. | Tool | Identifier | Subject | Location | Fix |",
          "|---|---|---|---|---|---|"]
    for f in sorted(rows, key=lambda x: SEV_RANK[x["severity"]])[:limit]:
        md.append(f"| {ICON[f['severity']]} | {f['tool']} | `{f['id']}` | "
                  f"{f['title']} | `{f['location']}` | {f['fixed'] or '—'} |")
    if len(rows) > limit:
        md.append(f"| … | | | _{len(rows) - limit} more_ | | |")
    md.append("")
    return md


# --------------------------------------------------------------------------- #
def active_exceptions(entries) -> set[str]:
    """An exception WITHOUT a valid expiration date (missing, or wrongly
    typed — e.g. `expires: "2026-12-31"` in quotes, which PyYAML keeps as
    a str rather than a date) is rejected, not kept active indefinitely.
    This is the behavior documented in the README ("Without expires, the
    script rejects it") — without this safeguard, a YAML typo would
    silently make an exception permanent."""
    today, active = date.today(), set()
    for exc in entries or []:
        exp = exc.get("expires")
        if isinstance(exp, datetime):
            exp = exp.date()
        if not isinstance(exp, date):
            print(f"::warning:: Exception with no valid expiration date for "
                  f"{exc.get('id')} — ignored (expected: an unquoted YAML "
                  f"date, e.g. expires: 2026-12-31).")
            continue
        if exp < today:
            print(f"::warning:: Exception expired on {exp} for "
                  f"{exc.get('id')} — it is blocking again.")
            continue
        if exc.get("id"):
            active.add(str(exc["id"]))
    return active


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input-dir", required=True, type=Path)
    ap.add_argument("--policy", required=True, type=Path)
    ap.add_argument("--output-dir", type=Path)
    ap.add_argument("--source-dir", type=Path, default=None,
                     help="Root of the scanned project. If provided, a context "
                          "excerpt (a few lines, secret redacted) is embedded in "
                          "each secret-type finding — useful for a preview in the "
                          "dashboard without having to reopen the project later.")
    ap.add_argument("--expect", default="",
                    help="Comma-separated scanners that were supposed to run "
                         f"({', '.join(EXPECTED_REPORTS)}): a missing report is a "
                         "coverage gap, blocking in enforce mode.")
    ap.add_argument("--gate-scope", choices=("all", "new"), default="all",
                    help="new: block only the findings and license violations "
                         "absent from --baseline on a merge request; outside "
                         "one, report them without blocking.")
    ap.add_argument("--merge-request", action="store_true",
                    help="This is a merge request pipeline (--gate-scope new).")
    ap.add_argument("--baseline", type=Path, default=None,
                    help="The target branch's security-report.json "
                         "(--gate-scope new). Missing or unreadable: full gate.")
    ap.add_argument("--baseline-ref", default="the target branch",
                    help="Name of the baseline's branch, for the report.")
    args = ap.parse_args()
    expected = [t.strip() for t in args.expect.split(",") if t.strip()]
    unknown = [t for t in expected if t not in EXPECTED_REPORTS]
    if unknown:
        ap.error(f"--expect: unknown scanner(s) {', '.join(unknown)} "
                 f"(expected: {', '.join(EXPECTED_REPORTS)})")
    out_dir = args.output_dir or args.input_dir
    d = args.input_dir

    try:
        policy = effective_policy(args.policy)
    except (OSError, ValueError) as exc:  # unreadable policy, missing lists_file, bad mode
        print(f"::error:: {exc}", file=sys.stderr)
        return 2
    # How --gate-scope new applies here: "compare" against the baseline,
    # "full" (merge request without a baseline) or "report" (outside a
    # merge request). "all": the plain gate.
    baseline = None
    scope_state = "all"
    if args.gate_scope == "new":
        if not args.merge_request:
            scope_state = "report"
        else:
            baseline = load_baseline(args.baseline)
            scope_state = "compare" if baseline else "full"
            if not baseline:
                print(f"::warning:: No usable report of {args.baseline_ref} to "
                      "compare with: full gate, every finding counts as new.")
    vuln_pol = policy.get("vulnerabilities", {}) or {}
    sast_pol = policy.get("sast", {}) or {}
    sec_pol = policy.get("secrets", {}) or {}

    findings: list[dict] = []
    findings += parse_grype(load(d / "grype.json"))
    findings += parse_osv(load(d / "osv.json"))
    findings += parse_semgrep(load(d / "semgrep.json"))
    findings += parse_gitleaks(load(d / "gitleaks.json"))
    findings += parse_trivy(load(d / "trivy-image.json"))
    findings += parse_trivy(load(d / "trivy-iac.json"), category="iac")
    reuse_data = load(d / "reuse.json")
    findings += parse_reuse(reuse_data)

    findings = deduplicate(findings)

    source_dir = (args.source_dir.resolve()
                  if args.source_dir and args.source_dir.is_dir() else None)
    for f in findings:
        if f.get("file"):
            f["file"] = project_relative(f["file"], source_dir)

    if source_dir:
        for f in findings:
            if f["category"] != "secret" or "extra" not in f:
                continue
            ctx = secret_context(source_dir, f["location"], f["extra"])
            if ctx:
                f["context"] = ctx
            del f["extra"]  # internal metadata, not meant for the final report
    else:
        for f in findings:
            f.pop("extra", None)

    # --- Applying the policy ---------------------------------------------------
    excepted = active_exceptions(vuln_pol.get("exceptions"))
    ignore_unfixed = bool(vuln_pol.get("ignore_unfixed", True))
    thresholds = {
        "vuln": vuln_pol.get("fail_on", "high"),
        "sast": sast_pol.get("fail_on", "high"),
        "iac": sast_pol.get("fail_on", "high"),
    }

    blocking = []
    would_block = []
    existing = []
    # Multiset: an MR adding a second occurrence of a known finding (same
    # rule, same file) still brings a new one.
    known = Counter(compare_key(f) for f in (baseline or {}).get("findings", [])
                    if isinstance(f, dict))
    for f in findings:
        # By ID or alias: the ID a merged finding keeps may be the other
        # scanner's (a GHSA for an exception written on its CVE or PYSEC).
        if f["id"] in excepted or excepted & set(f.get("aliases", [])):
            f["status"] = "exception"
            continue
        if f["category"] == "license_header":
            # Always reporting-only, by design — a sensitization signal
            # for the scanned project, not a compliance gate. See
            # parse_reuse()'s docstring.
            f["status"] = "info"
        elif f["category"] == "secret":
            f["status"] = "blocking" if sec_pol.get("fail_on_any", True) else "info"
        else:
            limit = thresholds.get(f["category"], "high")
            if limit == "none":
                f["status"] = "info"
            elif f["category"] == "vuln" and ignore_unfixed and not f["fixed"]:
                f["status"] = "sans-correctif"
            else:
                f["status"] = ("blocking"
                               if SEV_RANK[f["severity"]] <= SEV_RANK.get(limit, 1)
                               else "info")
        if f["status"] == "blocking":
            key = compare_key(f)
            if scope_state == "compare" and key is not None and known[key] > 0:
                # Already on the target branch: not brought by this MR.
                known[key] -= 1
                f["status"] = "existing"
                existing.append(f)
                continue
            # Audit mode for this category (see policy.py), or the
            # new-findings-only gate outside a merge request: reported as
            # "would-block", never blocking.
            section = CATEGORY_MODE_SECTION.get(f["category"])
            if scope_state == "report" or (
                    section and (policy.get(section) or {}).get("mode") == "audit"):
                f["status"] = "would-block"
                would_block.append(f)
            else:
                blocking.append(f)

    lic = load(d / "licenses.json") or {}
    lic_failed = bool(lic.get("failed"))
    lic_would_fail = bool(lic.get("would_fail")) and not lic_failed
    violations = license_violations(lic, policy.get("licenses", {}) or {})
    new_violations = None  # compared with the baseline only in "compare"
    lic_existing = False
    if scope_state == "report" and lic_failed:
        lic_failed, lic_would_fail = False, True
    elif scope_state == "compare" and isinstance(baseline.get("license_violations"), list):
        # A baseline written before the new-findings-only gate has no
        # license_violations: licenses then stay under the full gate.
        new_violations = sorted(set(violations) - set(baseline["license_violations"]))
        if (lic_failed or lic_would_fail) and not new_violations:
            lic_failed = lic_would_fail = False
            lic_existing = True
    audited = sorted(section for section in ("vulnerabilities", "sast", "secrets", "licenses")
                     if (policy.get(section) or {}).get("mode") == "audit")

    # Reporting-only, like REUSE: a degraded step never changes the verdict,
    # it only warns that the verdict rests on a partial scan.
    coverage = load(d / "coverage.json")
    gaps = [g for g in coverage if isinstance(g, dict)] if isinstance(coverage, list) else []
    # Unlike those, a missing report from an expected scanner can block.
    missing = expected_gaps(d, expected, policy)
    gaps += missing
    coverage_blocking = [g for g in missing if g["blocking"]]

    # --- Report -----------------------------------------------------------
    by_sev = Counter(f["severity"] for f in findings)
    by_cat = Counter(f["category"] for f in findings)
    failed = bool(blocking) or lic_failed or bool(coverage_blocking)

    md = ["# Security report", ""]
    if audited:
        md += [f"> ⚠️ **Audit mode** for: {', '.join(audited)}. Findings that would "
               "block in enforce mode are reported below but don't fail the pipeline.", ""]
    if scope_state == "compare":
        md += [f"> 🆕 **New findings only**: compared with the latest report of "
               f"`{args.baseline_ref}`. What's already there is listed under "
               "\"Already on the target branch\" and doesn't block.", ""]
    elif scope_state == "full":
        md += [f"> ⚠️ **New findings only** requested, but no report of "
               f"`{args.baseline_ref}` to compare with: full gate, every finding "
               "counts as new.", ""]
    elif scope_state == "report":
        md += ["> ℹ️ **New findings only**: outside a merge request there is "
               "nothing to compare with, so findings and licenses are reported "
               "without blocking. Coverage gaps still block.", ""]
    md += ["## Overview", "",
          "| Severity | Total |", "|---|---|"]
    md += [f"| {ICON[s]} {s.capitalize()} | {by_sev.get(s, 0)} |"
           for s in SEVERITIES if by_sev.get(s)]
    md += ["", "| Category | Total |", "|---|---|",
           f"| Dependencies (SCA) | {by_cat.get('vuln', 0)} |",
           f"| Code (SAST) | {by_cat.get('sast', 0)} |",
           f"| Secrets | {by_cat.get('secret', 0)} |",
           f"| Infra / IaC | {by_cat.get('iac', 0)} |", ""]

    if gaps:
        title = ("## ⛔ Incomplete coverage" if coverage_blocking
                 else "## ⚠️ Reduced coverage")
        md += [f"{title} ({len(gaps)} step(s) degraded)", "",
               "This is **not** a full scan: the steps below were skipped or "
               "failed, so the counts above are a floor, not a total.", ""]
        for g in gaps:
            note = (" → **blocking**" if g.get("blocking")
                    else " → not blocking (audit mode)" if "blocking" in g else "")
            md.append(f"- **{g.get('tool', '?')}** — {g.get('reason', '')}{note}")
        md.append("")

    if lic:
        s = lic.get("summary", {})
        md += ["## Licenses", "",
               f"✅ {s.get('allow', 0)} allowed · "
               f"⚠️ {s.get('review', 0)} to review · "
               f"⛔ {s.get('deny', 0)} denied"
               + ("  → **blocking**" if lic_failed else "")
               + ("  → **would block** (not enforced)" if lic_would_fail else "")
               + ("  → already on the target branch, not blocking"
                  if lic_existing else ""),
               ""]
        if new_violations and (lic_failed or lic_would_fail):
            md += ["New compared with the target branch:", ""]
            md += [f"- `{v}`" for v in new_violations[:25]]
            if len(new_violations) > 25:
                md.append(f"- … {len(new_violations) - 25} more")
            md.append("")
        md += ["Details: `licenses.md`", ""]

    reuse_findings = [f for f in findings if f["category"] == "license_header"]
    if reuse_data:
        unused = (reuse_data.get("non_compliant", {}) or {}).get("unused_licenses", []) or []
        md += ["## License headers (REUSE)", "",
               "Non-blocking, by design: a sensitization signal for "
               "SPDX-License-Identifier/copyright header adoption "
               "([reuse.software](https://reuse.software/)), not a "
               "compliance gate.",
               ""]
        if reuse_findings:
            md += [f"⚠️ {len(reuse_findings)} file(s) without a REUSE-compliant "
                   f"header — see `reuse.json`, or run `reuse lint` locally.", ""]
        else:
            md += ["✅ Every scanned file is REUSE-compliant.", ""]
        if unused:
            md += [f"ℹ️ {len(unused)} unused license text(s) under `LICENSES/` "
                   "(no file references them — safe to remove).", ""]

    if blocking:
        md += [f"## ⛔ Blocking ({len(blocking)})", ""] + findings_table(blocking)
    if would_block:
        md += [f"## ⚠️ Would block in enforce mode ({len(would_block)}, not enforced)", "",
               "Not blocking here (audit mode, or the new-findings-only gate "
               "outside a merge request) — to clear before enforcing.", ""
               ] + findings_table(would_block)
    if existing:
        md += [f"## 🗂️ Already on the target branch ({len(existing)}, not blocking)", "",
               f"Would block, but already in `{args.baseline_ref}`'s latest "
               "report, so not brought by this merge request: the backlog to "
               "clear.", ""] + findings_table(existing)

    unfixed = [f for f in findings if f.get("status") == "sans-correctif"
               and SEV_RANK[f["severity"]] <= 1]
    if unfixed:
        md += [f"## 🔭 No fix published yet ({len(unfixed)} critical/high)", "",
               "Non-blocking per policy. Track in Dependency-Track "
               "to be alerted as soon as a fix comes out.", ""]
        for f in unfixed[:25]:
            md.append(f"- {ICON[f['severity']]} `{f['id']}` — {f['title']}")
        md.append("")

    md.append("---")
    if failed:
        result = "❌ PIPELINE BLOCKED"
    elif would_block or lic_would_fail:
        result = "⚠️ OK, not enforced — would block in enforce mode"
    elif existing or lic_existing:
        result = "✅ OK — nothing new (backlog already on the target branch)"
    else:
        result = "✅ OK"
    md.append(f"**Result: {result}**"
              + (" _(reduced coverage — see above)_" if gaps else ""))
    report = "\n".join(md)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "security-report.md").write_text(report, encoding="utf-8")
    (out_dir / "security-report.json").write_text(json.dumps(
        {"failed": failed, "blocking": len(blocking),
         "would_block": len(would_block) + (1 if lic_would_fail else 0),
         "audit": audited,
         "gate_scope": {"scope": args.gate_scope, "state": scope_state,
                        "baseline_ref": args.baseline_ref
                        if scope_state in ("compare", "full") else None},
         "existing": len(existing) + (1 if lic_existing else 0),
         "license_violations": violations,
         "license_components": license_components(lic),
         "new_license_violations": new_violations,
         "distribution_model": (policy.get("meta") or {}).get("distribution_model"),
         "by_severity": dict(by_sev), "by_category": dict(by_cat),
         "licenses": lic.get("summary", {}),
         "reuse_compliant": bool((reuse_data or {}).get("summary", {}).get("compliant"))
                            if reuse_data else None,
         "coverage_gaps": gaps if (coverage is not None or expected) else None,
         "coverage_blocking": len(coverage_blocking),
         "findings": findings},
        indent=2, ensure_ascii=False), encoding="utf-8")

    print(report)
    if failed:
        print(f"\n::error:: {len(blocking)} blocking finding(s)"
              + (" + license policy violated" if lic_failed else "")
              + (" + incomplete coverage ("
                 + ", ".join(g["tool"] for g in coverage_blocking) + ")"
                 if coverage_blocking else ""),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
