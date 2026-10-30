#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""
Generate a self-contained HTML dashboard from the reports produced by
aggregate_report.py / license_gate.py.

Reads every <root>/<project>_<YYYYMMDD-HHMMSS>/security-report.json folder
created by analyze-archive.sh (or a single classic report folder), shows the
most recent run's state, and the trend over time when several runs exist.

Self-contained: no external dependency, no network call, all styling and
charts (inline SVG) live in the produced HTML file — consistent with the
"no code/data sent to a third party" constraint of the rest of the suite.

Usage:
    python generate_dashboard.py --reports-root security-reports \
                                  --output security-reports/dashboard.html

    # or a single report folder (no timestamped sub-folders):
    python generate_dashboard.py --reports-root security-reports/my-run \
                                  --output security-reports/my-run/dashboard.html
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from advisories import ADVISORY_URL_PATTERNS, advisory_url

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

# --- Palette (see dataviz skill — references/palette.md) --------------------
SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_STATUS = {"critical": "critical", "high": "serious", "medium": "warning", "low": "good"}
CATEGORY_LABELS = {"vuln": "Dependencies (SCA)", "sast": "Code (SAST)",
                    "secret": "Secrets", "iac": "Infra / IaC",
                    "license_header": "License headers (REUSE)"}
CATEGORY_ROLES = {"vuln": "critical", "sast": "serious", "secret": "critical", "iac": "warning",
                  "license_header": "good"}
LICENSE_LABELS = {"allow": "Allowed", "review": "Needs review", "deny": "Denied"}
LICENSE_ROLES = {"allow": "good", "review": "warning", "deny": "critical"}

def load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"::warning:: {path} unreadable ({exc}) — skipped.", file=sys.stderr)
        return None


def parse_run_id(dirname: str) -> tuple[str, datetime | None]:
    """Extracts (project-name, timestamp) from a '<project>_<YYYYMMDD-HHMMSS>' folder name."""
    if "_" in dirname:
        prefix, _, suffix = dirname.rpartition("_")
        try:
            ts = datetime.strptime(suffix, "%Y%m%d-%H%M%S")
            return prefix, ts
        except ValueError:
            pass
    return dirname, None


def parse_timestamp(dirname: str) -> datetime | None:
    try:
        return datetime.strptime(dirname, "%Y%m%d-%H%M%S")
    except ValueError:
        return None


def discover_runs(reports_root: Path) -> list[dict[str, Any]]:
    """Finds every security-report.json under reports_root. Supports three
    layouts, tried in order:

    1. reports_root itself is a single run (security-report.json directly inside).
    2. <reports_root>/<project>/<YYYYMMDD-HHMMSS>/security-report.json — the
       current analyze-archive.sh layout: one folder per analyzed project,
       one timestamped sub-folder per run.
    3. <reports_root>/<project>_<YYYYMMDD-HHMMSS>/security-report.json — the
       older flat layout, kept for backward compatibility with history
       collected before the two-level layout existed.
    """
    runs = []

    direct = reports_root / "security-report.json"
    if direct.is_file():
        data = load_json(direct)
        if data is not None:
            name, ts = parse_run_id(reports_root.name)
            runs.append({"dir": reports_root, "name": name, "timestamp": ts, "data": data})
        return runs

    if not reports_root.is_dir():
        return runs

    # Layout 2 seen from one level down: reports_root is itself a <project>
    # folder holding only <timestamp>/ run folders. That happens when scoping a
    # dashboard to a single project (--reports-root security-reports/<project>).
    # Without this, each run folder would be taken for a project and the
    # dashboard would be titled after a timestamp rather than the project.
    run_dirs = [d for d in sorted(reports_root.iterdir())
                if d.is_dir() and parse_timestamp(d.name) is not None
                and (d / "security-report.json").is_file()]
    if run_dirs:
        for run_dir in run_dirs:
            data = load_json(run_dir / "security-report.json")
            if data is None:
                continue
            runs.append({"dir": run_dir, "name": reports_root.name,
                         "timestamp": parse_timestamp(run_dir.name), "data": data})
        runs.sort(key=lambda r: r["timestamp"] or datetime.min)
        return runs

    for project_dir in sorted(reports_root.iterdir()):
        if not project_dir.is_dir():
            continue

        # Layout 2: <project>/<timestamp>/security-report.json
        found_nested = False
        for run_dir in sorted(project_dir.iterdir()):
            if not run_dir.is_dir():
                continue
            report = run_dir / "security-report.json"
            data = load_json(report)
            if data is None:
                continue
            found_nested = True
            ts = parse_timestamp(run_dir.name)
            runs.append({"dir": run_dir, "name": project_dir.name, "timestamp": ts, "data": data})

        if found_nested:
            continue

        # Layout 3 (legacy): <project>_<timestamp>/security-report.json,
        # i.e. project_dir itself is a run folder.
        report = project_dir / "security-report.json"
        data = load_json(report)
        if data is not None:
            name, ts = parse_run_id(project_dir.name)
            runs.append({"dir": project_dir, "name": name, "timestamp": ts, "data": data})

    runs.sort(key=lambda r: r["timestamp"] or datetime.min)
    return runs


def esc(s: Any) -> str:
    return html.escape(str(s), quote=True)


def json_for_script(value: Any) -> str:
    """JSON-encodes a value for embedding inside an inline <script> block, safe
    against scanned (untrusted) content — a finding title/location containing
    the literal text "</script>" would otherwise close the tag early and let
    arbitrary HTML/JS execute when the report is opened. Escaping "<" as
    "\\u003c" is the standard mitigation (valid inside a JSON string, and the
    browser's HTML parser no longer sees a tag). Used for every payload
    embedded in the page's <script> block, whether or not its origin looks
    trusted today — cheap to apply uniformly, and avoids relying on someone
    correctly judging "trusted" at each call site."""
    return json.dumps(value).replace("<", "\\u003c")


def js_str(s: Any) -> str:
    """JSON-encodes a value for safe embedding inside an inline JS string/attribute."""
    return json_for_script(str(s))


# --- Dashboard assembly --------------------------------------------------
# All charts, the findings table, and the run/project switching logic are
# rendered client-side (see the <script> block in build_html) — one code
# path serves the initial paint, a run switch, and a project switch, so
# they can never drift apart. The Python side only shapes the data payload.

def build_html(all_runs: list[dict[str, Any]], reports_root: Path, default_project: str) -> str:
    # Group all discovered runs by project name; each project's own runs are
    # sorted oldest -> newest (discover_runs already sorts globally by
    # timestamp, so a stable per-project filter preserves that order).
    projects: dict[str, list[dict]] = {}
    for r in all_runs:
        projects.setdefault(r["name"], []).append(r)
    project_names = sorted(projects)

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Full runs payload: every run of every project, keyed by run directory.
    # Charts, KPIs, findings table and run history are all rendered from this
    # in JS (see the script at the bottom) — the same code path serves the
    # initial paint, a run switch, and a project switch, so they can never
    # drift apart.
    runs_payload = {
        str(r["dir"]): {
            "project": r["name"],
            "timestamp": r["timestamp"].strftime("%Y-%m-%d %H:%M") if r["timestamp"] else None,
            "timestamp_short": r["timestamp"].strftime("%m-%d %H:%M") if r["timestamp"] else r["name"],
            "failed": bool(r["data"].get("failed")),
            "blocking": r["data"].get("blocking", 0),
            # Audit mode (policy.py), or the new-findings-only gate outside a
            # merge request: findings that would block in enforce mode.
            "would_block": r["data"].get("would_block", 0),
            # New-findings-only gate: would block, but already on the target branch.
            "existing": r["data"].get("existing", 0),
            "by_severity": r["data"].get("by_severity", {}),
            "by_category": r["data"].get("by_category", {}),
            "licenses": r["data"].get("licenses", {}),
            # Components not allowed (review/deny), for the Licenses tab;
            # None in a report written before they were kept.
            "license_components": r["data"].get("license_components"),
            "findings": r["data"].get("findings", []),
        }
        for r in all_runs
    }

    # Portfolio payload: one summary row per project (its most recent run),
    # used by the landing screen and kept in sync with runs_payload — no
    # separate source of truth to drift.
    portfolio_payload = []
    for name in project_names:
        runs_for_project = projects[name]
        latest = runs_for_project[-1]
        d = latest["data"]
        portfolio_payload.append({
            "name": name,
            "runDir": str(latest["dir"]),
            "runCount": len(runs_for_project),
            "timestamp": latest["timestamp"].strftime("%Y-%m-%d %H:%M") if latest["timestamp"] else None,
            "failed": bool(d.get("failed")),
            "blocking": d.get("blocking", 0),
            "totalFindings": sum(d.get("by_severity", {}).values()),
            "deniedLicenses": d.get("licenses", {}).get("deny", 0),
        })

    default_run_dir = str(projects[default_project][-1]["dir"])

    # A single-project dashboard opens straight on that project's view (see the
    # PORTFOLIO.length check in the script below), so name it after the project
    # instead of the generic portfolio title. The browser tab is static HTML and
    # cannot be renamed later by switchProject(), unlike the <h1>.
    page_title = ("Security dashboard" if len(project_names) > 1
                  else f"Security dashboard — {default_project}")

    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(page_title)}</title>
<style>
:root {{
  color-scheme: light;
  --surface-1: #fcfcfb;
  --page: #f9f9f7;
  --text-primary: #0b0b0b;
  --text-secondary: #52514e;
  --text-muted: #898781;
  --grid: #e1e0d9;
  --baseline: #c3c2b7;
  --border: rgba(11,11,11,0.10);
  --status-good: #0ca30c;
  --status-warning: #fab219;
  --status-serious: #ec835a;
  --status-critical: #d03b3b;
  --accent-wash: rgba(42,120,214,0.08);
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    color-scheme: dark;
    --surface-1: #1a1a19;
    --page: #0d0d0d;
    --text-primary: #ffffff;
    --text-secondary: #c3c2b7;
    --text-muted: #898781;
    --grid: #2c2c2a;
    --baseline: #383835;
    --border: rgba(255,255,255,0.10);
    --accent-wash: rgba(57,135,229,0.12);
  }}
}}
:root[data-theme="dark"] {{
  color-scheme: dark;
  --surface-1: #1a1a19;
  --page: #0d0d0d;
  --text-primary: #ffffff;
  --text-secondary: #c3c2b7;
  --text-muted: #898781;
  --grid: #2c2c2a;
  --baseline: #383835;
  --border: rgba(255,255,255,0.10);
  --accent-wash: rgba(57,135,229,0.12);
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background: var(--page);
  color: var(--text-primary);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  padding: 24px;
}}
.wrap {{ max-width: 1100px; margin: 0 auto; }}
header {{ margin-bottom: 24px; }}
h1 {{ font-size: 1.5rem; margin: 0 0 4px; }}
.meta {{ color: var(--text-secondary); font-size: 0.9rem; }}
.kpi-row {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
}}
.stat-tile {{
  background: var(--surface-1);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
}}
.stat-clickable {{ cursor: pointer; }}
.stat-clickable:hover, .stat-clickable:focus-visible {{ background: var(--accent-wash); outline: none; }}
.stat-clickable:focus-visible {{ outline: 2px solid var(--status-good); outline-offset: 2px; }}
.stat-value {{ font-size: 2rem; font-weight: 600; }}
.stat-label {{ color: var(--text-secondary); font-size: 0.85rem; margin-top: 4px; }}
.stat-critical .stat-value {{ color: var(--status-critical); }}
.stat-good .stat-value {{ color: var(--status-good); }}
.stat-warning .stat-value {{ color: color-mix(in srgb, var(--status-warning) 70%, black); }}
.grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(420px, 1fr));
  gap: 16px;
}}
.chart {{
  background: var(--surface-1);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
}}
.chart-wide {{ grid-column: 1 / -1; }}
.chart h3 {{ margin: 0 0 4px; font-size: 1rem; }}
.chart-subtitle {{ color: var(--text-muted); font-size: 0.8rem; margin: 0 0 8px; }}
.chart-empty {{ color: var(--text-muted); padding: 16px; font-size: 0.9rem; }}
.chart-svg {{ width: 100%; height: auto; overflow: visible; }}
.bar-label {{ fill: var(--text-secondary); font-size: 12px; }}
.bar-track {{ fill: var(--grid); rx: 4; }}
.bar-value {{ fill: var(--text-primary); font-size: 12px; font-weight: 600; }}
.bar-row-clickable {{ cursor: pointer; }}
.bar-row-clickable:hover .bar-fill, .bar-row-clickable:focus-visible .bar-fill {{ opacity: 0.8; }}
.bar-row-clickable:hover .bar-track, .bar-row-clickable:focus-visible .bar-track {{ fill: var(--accent-wash); }}
.bar-row:focus-visible {{ outline: 2px solid var(--status-good); outline-offset: 2px; }}
.trend-baseline {{ stroke: var(--baseline); stroke-width: 1; }}
.trend-tick {{ fill: var(--text-muted); font-size: 10px; }}
.trend-endlabel {{ fill: var(--text-primary); font-size: 12px; font-weight: 600; }}
.trend-dot {{ cursor: pointer; }}
.trend-dot:hover, .trend-dot:focus-visible {{ r: 9; outline: none; }}
.table-header {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; }}
.table-header h3 {{ margin: 0; }}
.clear-filter-btn {{
  background: var(--status-critical);
  color: #fff;
  border: none;
  border-radius: 6px;
  padding: 4px 10px;
  font-size: 0.8rem;
  cursor: pointer;
}}
.clear-filter-btn:hover {{ opacity: 0.85; }}
.table-scroll {{ overflow-x: auto; }}
.findings-tabs {{ display: flex; flex-wrap: wrap; gap: 2px; border-bottom: 1px solid var(--grid); margin: 4px 0 8px; }}
.findings-tab {{
  background: none; border: none; border-bottom: 2px solid transparent; margin-bottom: -1px;
  padding: 6px 12px; color: var(--text-secondary); font: inherit; font-size: 0.85rem; cursor: pointer;
}}
.findings-tab:hover, .findings-tab:focus-visible {{ color: var(--text-primary); background: var(--accent-wash); outline: none; }}
.findings-tab[aria-selected="true"] {{ color: var(--text-primary); font-weight: 600; border-bottom-color: var(--text-primary); }}
.findings-tab .tab-count {{ color: var(--text-muted); font-weight: 400; margin-left: 4px; }}
/* Not a findings tab (ALL doesn't count it): on the right, past a separator. */
.findings-tab.tab-aside {{ margin-left: auto; border-left: 1px solid var(--grid); }}
#findings-title {{ cursor: help; }}
/* Group row: the component's name in the ID column, its count and severity
   bar at the start of the Title column — same place and width on every row. */
.group-stats {{ display: inline-flex; align-items: center; gap: 8px; }}
.group-count {{ min-width: 4ch; text-align: right; font-variant-numeric: tabular-nums; color: var(--text-secondary); }}
.sev-bar {{ flex: 0 0 160px; display: flex; height: 10px; border-radius: 5px; overflow: hidden; background: var(--grid); }}
.sev-bar > span {{ height: 100%; }}
.sev-bar .seg-critical {{ background: var(--status-critical); }}
.sev-bar .seg-high {{ background: var(--status-serious); }}
.sev-bar .seg-medium {{ background: var(--status-warning); }}
.sev-bar .seg-low {{ background: var(--status-good); }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--grid); white-space: nowrap; }}
/* The title wraps instead of widening the table: SAST messages are long. */
td.cell-title {{ white-space: normal; }}
/* On an inner block: a min-width on the cell itself isn't kept by the table layout. */
td.cell-title > div {{ min-width: 280px; max-width: 560px; }}
th {{ color: var(--text-muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; }}
td code {{ font-family: ui-monospace, monospace; font-size: 0.8rem; color: var(--text-secondary); }}
a.advisory-link {{ text-decoration: none; }}
a.advisory-link code {{ color: var(--status-good); text-decoration: underline; text-decoration-color: color-mix(in srgb, var(--status-good) 40%, transparent); }}
a.advisory-link:hover code, a.advisory-link:focus-visible code {{ text-decoration-color: var(--status-good); }}
.modal-fields a.advisory-link code {{ background: var(--grid); padding: 2px 6px; border-radius: 4px; }}
.sev-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }}
.sev-critical {{ background: var(--status-critical); }}
.sev-high {{ background: var(--status-serious); }}
.sev-medium {{ background: var(--status-warning); }}
.sev-low {{ background: var(--status-good); }}
.runs-table {{ margin-top: 24px; }}
.run-current td {{ font-weight: 600; }}
.run-row-clickable {{ cursor: pointer; }}
.run-row-clickable:hover, .run-row-clickable:focus-visible {{ background: var(--accent-wash); outline: none; }}
tr[data-finding-index] {{ cursor: pointer; }}
tr[data-finding-index]:hover, tr[data-finding-index]:focus-visible {{ background: var(--accent-wash); outline: none; }}
tr.group-summary-row {{ cursor: pointer; font-weight: 600; }}
tr.group-summary-row:hover, tr.group-summary-row:focus-visible {{ background: var(--accent-wash); outline: none; }}
tr.group-summary-row[aria-expanded="true"] .group-caret {{ display: inline-block; transform: rotate(90deg); }}
.group-caret {{ display: inline-block; color: var(--text-muted); font-size: 0.75rem; margin-right: 4px; transition: transform 0.1s ease; }}
tr.finding-nested-row td:first-child {{ padding-left: 26px; }}
.back-link {{
  background: none; border: none; color: var(--text-secondary); font-size: 0.85rem;
  cursor: pointer; padding: 4px 0; margin-bottom: 12px; display: inline-block;
}}
.back-link:hover, .back-link:focus-visible {{ color: var(--text-primary); outline: none; text-decoration: underline; }}
#portfolio-table tr[data-open-project] td:first-child {{ font-weight: 600; }}
footer {{ margin-top: 32px; color: var(--text-muted); font-size: 0.8rem; }}

/* Finding detail modal */
.modal-backdrop {{
  position: fixed; inset: 0; background: rgba(0,0,0,0.5);
  display: flex; align-items: center; justify-content: center;
  padding: 24px; z-index: 100;
}}
.modal-backdrop[hidden] {{ display: none; }}
.modal {{
  background: var(--surface-1);
  border: 1px solid var(--border);
  border-radius: 12px;
  max-width: 640px; width: 100%; max-height: 85vh; overflow-y: auto;
  padding: 24px;
  box-shadow: 0 20px 60px rgba(0,0,0,0.3);
}}
.modal-header {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 4px; }}
.modal-title {{ font-size: 1.15rem; font-weight: 600; margin: 0; }}
.modal-close {{
  background: none; border: none; color: var(--text-muted); font-size: 1.4rem;
  line-height: 1; cursor: pointer; padding: 4px 8px; border-radius: 6px; flex-shrink: 0;
}}
.modal-close:hover, .modal-close:focus-visible {{ background: var(--grid); color: var(--text-primary); outline: none; }}
.modal-badges {{ display: flex; gap: 8px; flex-wrap: wrap; margin: 8px 0 20px; }}
.badge {{
  display: inline-flex; align-items: center; gap: 5px;
  padding: 3px 10px; border-radius: 999px; font-size: 0.78rem; font-weight: 600;
  background: var(--grid); color: var(--text-secondary);
}}
.badge-critical {{ background: color-mix(in srgb, var(--status-critical) 16%, transparent); color: var(--status-critical); }}
.badge-serious {{ background: color-mix(in srgb, var(--status-serious) 16%, transparent); color: var(--status-serious); }}
.badge-warning {{ background: color-mix(in srgb, var(--status-warning) 20%, transparent); color: color-mix(in srgb, var(--status-warning) 70%, black); }}
.badge-good {{ background: color-mix(in srgb, var(--status-good) 16%, transparent); color: var(--status-good); }}
.modal-fields {{ display: grid; grid-template-columns: 120px 1fr; gap: 10px 16px; font-size: 0.9rem; }}
.modal-fields dt {{ color: var(--text-muted); font-weight: 600; font-size: 0.78rem; text-transform: uppercase; align-self: start; padding-top: 2px; }}
.modal-fields dd {{ margin: 0; color: var(--text-primary); word-break: break-word; }}
.modal-fields dd code {{ font-family: ui-monospace, monospace; font-size: 0.85rem; background: var(--grid); padding: 2px 6px; border-radius: 4px; }}
.modal-fields dd.dd-muted {{ color: var(--text-muted); }}

/* Secret finding: redacted code preview */
.code-preview {{ margin-top: 16px; }}
.code-preview-header {{ color: var(--text-muted); font-size: 0.78rem; font-weight: 600; text-transform: uppercase; margin-bottom: 6px; }}
.code-preview pre {{
  margin: 0; padding: 10px 0; background: var(--page); border: 1px solid var(--border);
  border-radius: 8px; overflow-x: auto; font-family: ui-monospace, monospace; font-size: 0.82rem;
}}
.code-preview-line {{ display: flex; padding: 1px 12px; white-space: pre; }}
.code-preview-line.highlight {{ background: color-mix(in srgb, var(--status-critical) 14%, transparent); border-left: 3px solid var(--status-critical); padding-left: 9px; }}
.code-preview-lineno {{ color: var(--text-muted); user-select: none; width: 3.5em; flex-shrink: 0; text-align: right; margin-right: 14px; }}
.code-preview-text {{ color: var(--text-primary); }}
.code-preview-note {{ color: var(--text-muted); font-size: 0.78rem; margin-top: 6px; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1 id="page-title">{esc(page_title)}</h1>
    <p class="meta" id="page-meta">{len(project_names)} project(s), {len(all_runs)} run(s) archived under <code>{esc(reports_root)}</code></p>
  </header>

  <!-- Portfolio view: landing screen, lists every project found under
       --reports-root. Hidden once a project is opened. -->
  <section id="portfolio-view">
    <div class="chart chart-wide">
      <h3>Projects</h3>
      <p class="chart-subtitle">Click a project to open its dashboard</p>
      <div class="table-scroll">
        <table id="portfolio-table">
          <thead><tr><th>Project</th><th>Status</th><th>Last run</th><th>Blocking</th><th>Findings</th><th>Denied licenses</th><th>Runs</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- Project view: one project's dashboard (KPIs, charts, trend, findings,
       run history). Hidden until a project is selected; everything inside
       is rendered by JS from RUNS/PORTFOLIO so the same code path serves the
       initial paint, a run switch, and a project switch. -->
  <section id="project-view" hidden>
    <button type="button" id="back-to-portfolio" class="back-link">← All projects</button>
    <p class="meta" id="run-meta"></p>

    <section class="kpi-row" id="kpi-row"></section>

    <section class="grid">
      <div class="chart" id="chart-severity"><h3>Findings by severity</h3><p class="chart-subtitle">Click a bar for details</p><svg class="chart-svg" role="img" aria-label="Findings by severity"></svg></div>
      <div class="chart" id="chart-category"><h3>Findings by category</h3><p class="chart-subtitle">Click a bar for details</p><svg class="chart-svg" role="img" aria-label="Findings by category"></svg></div>
      <div class="chart" id="chart-licenses"><h3>License compliance</h3><p class="chart-subtitle">Click a bar to list the components (every one in licenses.md)</p><svg class="chart-svg" role="img" aria-label="License compliance"></svg></div>
      <div class="chart" id="chart-fix"><h3>Fix availability</h3><p class="chart-subtitle">Dependency findings — click a bar for details</p><svg class="chart-svg" role="img" aria-label="Fix availability"></svg></div>
      <div class="chart chart-wide" id="chart-trend" hidden><h3 id="chart-trend-title">Blocking findings over time</h3><p class="chart-subtitle">Click a point to jump to that run</p><svg class="chart-svg" role="img" aria-label="Blocking findings over time"></svg></div>

      <div class="chart chart-wide" id="findings-panel">
        <div class="table-header">
          <h3 id="findings-title">Findings</h3>
          <button type="button" id="clear-filter" class="clear-filter-btn" hidden>Clear filter ×</button>
        </div>
        <p class="chart-subtitle" id="findings-subtitle" hidden></p>
        <div class="findings-tabs" id="findings-tabs" role="tablist" aria-label="Finding categories"></div>
        <div class="table-scroll">
          <table id="findings-table">
            <thead id="findings-head"></thead>
            <tbody></tbody>
          </table>
        </div>
        <p class="chart-subtitle" id="no-results" hidden>No findings match this filter.</p>
      </div>
    </section>

    <section class="runs-table chart" id="run-history-section" hidden>
      <h3>Run history</h3>
      <p class="chart-subtitle">Click a row to view that run's findings</p>
      <div class="table-scroll">
        <table>
          <thead><tr><th>Date</th><th>Status</th><th>Blocking</th><th>Findings</th></tr></thead>
          <tbody id="run-history-body"></tbody>
        </table>
      </div>
    </section>
  </section>

  <footer>Generated on {esc(generated_at)} by generate_dashboard.py — static page, no data sent to a third party.</footer>
</div>

<div class="modal-backdrop" id="finding-modal" hidden>
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div class="modal-header">
      <h2 class="modal-title" id="modal-title"></h2>
      <button type="button" class="modal-close" id="modal-close" aria-label="Close">×</button>
    </div>
    <div class="modal-badges" id="modal-badges"></div>
    <dl class="modal-fields" id="modal-fields"></dl>
    <div id="modal-code-preview" hidden></div>
  </div>
</div>

<script>
(function () {{
  "use strict";
  var RUNS = {json_for_script(runs_payload)};
  var PORTFOLIO = {json_for_script(portfolio_payload)};
  var DEFAULT_RUN = {js_str(default_run_dir)};
  var CURRENT_RUN = null;
  var SEVERITY_ORDER = ["critical", "high", "medium", "low"];
  // Every severity aggregate_report.py writes, most severe first: the sort
  // order of the findings table.
  var SEVERITY_RANK = ["critical", "high", "medium", "low", "negligible", "unknown"];
  // Order of the findings tabs after All (a category not listed comes last).
  var CATEGORY_TAB_ORDER = ["vuln", "sast", "secret", "iac", "license_header"];
  // Shorter than CATEGORY_LABELS: they sit side by side above the table.
  var TAB_LABELS = {{ all: "ALL", vuln: "Dependencies SCA", sast: "Code SAST", secret: "Secrets",
                     iac: "Infra IaC", license_header: "Headers", licenses: "Licenses" }};
  // A component the license gate didn't allow, by what to do about it:
  // a denied license, a known license to review, or no license found at all
  // (the policy's `unknown` verdict: find the license, not a legal call).
  var LICENSE_KINDS = ["deny", "review", "none"];
  var LICENSE_KIND_LABELS = {{ deny: "Denied", review: "License to review", none: "No license found" }};
  var LICENSE_KIND_ROLES = {{ deny: "critical", review: "warning", none: "serious" }};
  // Fix availability of the dependency findings (Fix availability chart).
  var FIX_KINDS = ["blocking", "other", "none"];
  var FIX_LABELS = {{ blocking: "Fixable, blocking", other: "Fixable, not blocking", none: "No fix yet" }};
  var FIX_ROLES = {{ blocking: "critical", other: "warning", none: "serious" }};
  var SEVERITY_STATUS = {json_for_script(SEVERITY_STATUS)};
  var CATEGORY_LABELS = {json_for_script(CATEGORY_LABELS)};
  var CATEGORY_ROLES = {json_for_script(CATEGORY_ROLES)};
  var LICENSE_LABELS = {json_for_script(LICENSE_LABELS)};
  var LICENSE_ROLES = {json_for_script(LICENSE_ROLES)};
  var ADVISORY_URL_PATTERNS = {json_for_script(ADVISORY_URL_PATTERNS)};

  function advisoryUrl(findingId) {{
    for (var i = 0; i < ADVISORY_URL_PATTERNS.length; i++) {{
      var prefix = ADVISORY_URL_PATTERNS[i][0];
      var template = ADVISORY_URL_PATTERNS[i][1];
      if (findingId && findingId.indexOf(prefix) === 0) {{
        return template.replace("{{id}}", findingId);
      }}
    }}
    return null;
  }}

  var tbody = document.querySelector("#findings-table tbody");
  var findingsHead = document.getElementById("findings-head");
  var findingsTabs = document.getElementById("findings-tabs");
  var findingsTitle = document.getElementById("findings-title");
  var findingsSubtitle = document.getElementById("findings-subtitle");
  var noResults = document.getElementById("no-results");
  var clearBtn = document.getElementById("clear-filter");
  var runMeta = document.getElementById("run-meta");
  var portfolioView = document.getElementById("portfolio-view");
  var projectView = document.getElementById("project-view");
  var portfolioBody = document.querySelector("#portfolio-table tbody");
  var kpiRow = document.getElementById("kpi-row");
  var pageTitle = document.getElementById("page-title");
  var pageMeta = document.getElementById("page-meta");
  var runHistorySection = document.getElementById("run-history-section");
  var runHistoryBody = document.getElementById("run-history-body");

  function sevDot(sev) {{
    return '<span class="sev-dot sev-' + sev + '"></span>';
  }}

  function statTileHtml(label, value, role, filterKey, filterVal) {{
    var cls = role ? " stat-" + role : "";
    var attrs = "";
    if (filterKey) {{
      cls += " stat-clickable";
      attrs = ' tabindex="0" role="button" data-filter-key="' + escText(filterKey) +
        '" data-filter-value="' + escText(filterVal) + '" data-filter-label="' + escText(label) +
        '" aria-label="Filter by ' + escText(label) + '"';
    }}
    return '<div class="stat-tile' + cls + '"' + attrs + '>' +
      '<div class="stat-value">' + escText(value) + '</div>' +
      '<div class="stat-label">' + escText(label) + '</div></div>';
  }}

  // --- Bar chart (severity / category / licenses / fix) -----------------
  // items: [{{label, value, role, filterVal}}, ...]. filterKey "" disables
  // click-to-filter for that chart (licenses of a report without the list
  // of components: only the hover tooltip carries the number there).
  function renderBarChart(svgEl, items, filterKey) {{
    if (!items.length) {{
      svgEl.outerHTML = '<div class="chart-empty">No data</div>';
      return;
    }}
    var maxVal = items.reduce(function (m, it) {{ return Math.max(m, it.value); }}, 0) || 1;
    var rowH = 28, gap = 10, labelW = 150, chartW = 360;
    var height = items.length * (rowH + gap) - gap + 20;
    svgEl.setAttribute("viewBox", "0 0 " + (labelW + chartW + 50) + " " + height);
    var rows = items.map(function (it, i) {{
      var y = i * (rowH + gap) + 10;
      var w = it.value ? Math.max(2, Math.round((it.value / maxVal) * chartW)) : 0;
      var color = "var(--status-" + it.role + ")";
      // An item without filterVal (License compliance's Allowed: not listed) stays plain.
      var clickable = it.value > 0 && !!filterKey && it.filterVal !== "";
      var cursorCls = clickable ? " bar-row-clickable" : "";
      var attrs = clickable
        ? ' data-filter-key="' + escText(filterKey) + '" data-filter-value="' + escText(it.filterVal) +
          '" data-filter-label="' + escText(it.label) + '" role="button" aria-label="Filter by ' +
          escText(it.label) + ": " + it.value + '"'
        : ' aria-label="' + escText(it.label) + ": " + it.value + '"';
      return '<g class="bar-row' + cursorCls + '" tabindex="0"' + attrs + '>' +
        '<text x="' + (labelW - 8) + '" y="' + (y + rowH / 2) + '" class="bar-label" text-anchor="end" dominant-baseline="middle">' + escText(it.label) + '</text>' +
        '<rect x="' + labelW + '" y="' + y + '" width="' + chartW + '" height="' + rowH + '" class="bar-track"/>' +
        '<rect x="' + labelW + '" y="' + y + '" width="' + w + '" height="' + rowH + '" rx="4" fill="' + color + '" class="bar-fill"/>' +
        '<text x="' + (labelW + Math.max(w, 0) + 8) + '" y="' + (y + rowH / 2) + '" class="bar-value" dominant-baseline="middle">' + it.value + '</text>' +
        '<title>' + escText(it.label) + ": " + it.value + (clickable ? " — click for details" : "") + '</title></g>';
    }});
    svgEl.innerHTML = rows.join("");
  }}

  // --- Trend chart (blocking findings over time, current project only) ---
  function renderTrendChart(svgEl, points) {{
    var w = 640, h = 160, pad = 28;
    var maxVal = points.reduce(function (m, p) {{ return Math.max(m, p.value); }}, 0) || 1;
    var n = points.length;
    var step = n > 1 ? (w - 2 * pad) / (n - 1) : 0;
    function xy(i, v) {{
      return {{ x: pad + i * step, y: h - pad - (v / maxVal) * (h - 2 * pad) }};
    }}
    var coords = points.map(function (p, i) {{ return xy(i, p.value); }});
    var path = "M " + coords.map(function (c) {{ return c.x.toFixed(1) + " " + c.y.toFixed(1); }}).join(" L ");
    var dots = points.map(function (p, i) {{
      var c = coords[i];
      return '<circle cx="' + c.x.toFixed(1) + '" cy="' + c.y.toFixed(1) + '" r="7" fill="var(--status-critical)" ' +
        'stroke="var(--surface-1)" stroke-width="2" class="trend-dot" tabindex="0" role="button" ' +
        'data-filter-key="run" data-filter-value="' + escText(p.runDir) + '" data-filter-label="' + escText(p.label) +
        '" aria-label="Show run ' + escText(p.label) + ": " + p.value + ' blocking"><title>' +
        escText(p.label) + ": " + p.value + ' blocking — click for details</title></circle>';
    }});
    var labels = points.map(function (p, i) {{
      if (i === 0 || i === n - 1 || n <= 6) {{
        var c = coords[i];
        return '<text x="' + c.x.toFixed(1) + '" y="' + (h - 6) + '" class="trend-tick" text-anchor="middle">' + escText(p.label) + '</text>';
      }}
      return "";
    }}).join("");
    var lastC = coords[n - 1];
    var endLabel = '<text x="' + (lastC.x - 6).toFixed(1) + '" y="' + (lastC.y - 12).toFixed(1) +
      '" class="trend-endlabel" text-anchor="end">' + points[n - 1].value + '</text>';
    svgEl.setAttribute("viewBox", "0 0 " + w + " " + h);
    svgEl.innerHTML =
      '<line x1="' + pad + '" y1="' + (h - pad) + '" x2="' + (w - pad) + '" y2="' + (h - pad) + '" class="trend-baseline"/>' +
      '<path d="' + path + '" fill="none" stroke="var(--status-critical)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>' +
      dots.join("") + endLabel + labels;
  }}

  function escText(s) {{
    var d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
  }}

  var visibleFindings = [];

  function sevRank(sev) {{
    var i = SEVERITY_RANK.indexOf(sev || "unknown");
    return i === -1 ? SEVERITY_RANK.length : i;
  }}

  // The component a dependency finding is on: its purl without qualifiers
  // or subpath, percent-decoded — what aggregate_report.py's normalize_purl()
  // writes, applied again here so that runs archived before it group the
  // same way (`...@2.9.8` and `...@2.9.8?type=jar` are one component).
  function groupLocation(f) {{
    var loc = f.location || "";
    if (f.category !== "vuln" || loc.indexOf("pkg:") !== 0) return loc;
    loc = loc.split("#")[0].split("?")[0];
    try {{ return decodeURIComponent(loc); }} catch (e) {{ return loc; }}
  }}

  // Groups findings sharing the same category and location (the component,
  // for dependencies: a dozen CVEs on one library) — a filter or a run
  // switch regroups the same way. Most severe first: groups by their worst
  // finding, then by size; findings by severity inside a group.
  function groupFindings(findings) {{
    var byKey = {{}};
    findings.forEach(function (f) {{
      var location = groupLocation(f);
      var key = (f.category || "") + "\\u0000" + location;
      if (!byKey[key]) {{
        byKey[key] = {{ category: f.category || "", location: location, items: [] }};
      }}
      byKey[key].items.push(f);
    }});
    var groups = Object.keys(byKey).map(function (k) {{
      var g = byKey[k];
      g.items.sort(function (a, b) {{
        return sevRank(a.severity) - sevRank(b.severity) ||
          String(a.id || "").localeCompare(String(b.id || ""));
      }});
      g.worst = sevRank(g.items[0].severity);
      return g;
    }});
    return groups.sort(function (a, b) {{
      return a.worst - b.worst || b.items.length - a.items.length ||
        a.location.localeCompare(b.location);
    }});
  }}

  // "3 critical · 12 high": a group's findings per severity, most severe first.
  function severityBreakdown(items) {{
    var counts = {{}};
    items.forEach(function (it) {{
      var s = it.severity || "unknown";
      counts[s] = (counts[s] || 0) + 1;
    }});
    return Object.keys(counts).sort(function (a, b) {{ return sevRank(a) - sevRank(b); }})
      .map(function (s) {{ return counts[s] + " " + s; }}).join(" · ");
  }}

  // A group's name past GROUP_LABEL_MAX characters, cut at the last space
  // before the limit (a long version goes first: `golang.org/x/crypto…`),
  // else at the limit, with an ellipsis. The full name is the tooltip.
  var GROUP_LABEL_MAX = 30;
  function shortLabel(label) {{
    if (label.length <= GROUP_LABEL_MAX) return label;
    var cut = label.slice(0, GROUP_LABEL_MAX);
    var space = cut.lastIndexOf(" ");
    return (space > 0 ? cut.slice(0, space) : cut) + "…";
  }}

  // A group's critical / high / medium / low findings as one bar of fixed
  // width, each severity's share proportional to its count (unknown and
  // negligible left out); the full breakdown in its tooltip.
  function severityBarHtml(items) {{
    var counts = {{ critical: 0, high: 0, medium: 0, low: 0 }};
    items.forEach(function (it) {{
      if (counts.hasOwnProperty(it.severity)) counts[it.severity]++;
    }});
    var total = counts.critical + counts.high + counts.medium + counts.low;
    var breakdown = escText(severityBreakdown(items));
    var segments = total ? ["critical", "high", "medium", "low"].filter(function (s) {{ return counts[s]; }})
      .map(function (s) {{
        return "<span class=\\"seg-" + s + "\\" style=\\"width:" + (100 * counts[s] / total).toFixed(2) + "%\\"></span>";
      }}).join("") : "";
    return "<span class=\\"sev-bar\\" title=\\"" + breakdown + "\\" role=\\"img\\" aria-label=\\"" + breakdown + "\\">" +
      segments + "</span>";
  }}

  // Every scanner that reported a group's findings (`grype+osv` split).
  function groupTools(items) {{
    var tools = [];
    items.forEach(function (it) {{
      String(it.tool || "").split("+").forEach(function (t) {{
        if (t && tools.indexOf(t) === -1) tools.push(t);
      }});
    }});
    return tools.join(", ") || "—";
  }}

  // What a group is about, readable without scrolling to the Location
  // column: for a dependency the component's name and version, from its
  // purl so that it doesn't depend on which scanner's titles are shown
  // (`jackson-databind 2.9.8`: a Maven groupId is left out, a Go module
  // path kept); else the location.
  function groupLabel(g) {{
    var loc = g.location || "";
    if (g.category !== "vuln" || loc.indexOf("pkg:") !== 0) return loc || "—";
    var type = loc.slice(4, loc.indexOf("/"));
    var path = loc.slice(loc.indexOf("/") + 1);
    var at = path.lastIndexOf("@");
    var name = at === -1 ? path : path.slice(0, at);
    if (type === "maven") name = name.split("/").pop();
    return name + (at === -1 ? "" : " " + path.slice(at + 1));
  }}

  // A rule ID of a code finding (Semgrep's `python.flask.security.injection.
  // subprocess-injection.subprocess-injection`) shows its last segment, the
  // rule name; the full ID stays in the tooltip and the details. Advisory
  // IDs are short and shown whole.
  function idCellHtml(findingId, category) {{
    var id = findingId || "—";
    var url = advisoryUrl(id);
    if (!url) {{
      var shortId = (category === "sast" || category === "iac") && id.indexOf(".") !== -1
        ? id.slice(id.lastIndexOf(".") + 1) : id;
      return "<code title=\\"" + escText(id) + "\\">" + escText(shortId || id) + "</code>";
    }}
    return "<a href=\\"" + escText(url) + "\\" target=\\"_blank\\" rel=\\"noopener noreferrer\\" " +
      "class=\\"advisory-link\\" onclick=\\"event.stopPropagation()\\"><code>" + escText(id) + "</code></a>";
  }}

  // The Category column only on the All tab: a category tab gives its room
  // to the title.
  function findingsHeadHtml(showCategory) {{
    return "<tr><th>Sev.</th>" + (showCategory ? "<th>Category</th>" : "") +
      "<th>Tool</th><th>ID</th><th>Title</th><th>Location</th><th>Fix</th><th>Gate status</th></tr>";
  }}

  function findingRowHtml(f, idx, nested, showCategory) {{
    var sev = f.severity || "low";
    var catLabel = CATEGORY_LABELS[f.category] || f.category || "—";
    var rowCls = nested ? " class=\\"finding-nested-row\\"" : "";
    var hiddenAttr = nested ? " hidden" : "";
    return "<tr" + rowCls + hiddenAttr + " data-severity=\\"" + escText(sev) + "\\" data-category=\\"" + escText(f.category || "") +
      "\\" data-status=\\"" + escText(f.status || "") + "\\" data-finding-index=\\"" + idx +
      "\\" tabindex=\\"0\\" role=\\"button\\" aria-label=\\"View details\\">" +
      "<td>" + sevDot(escText(sev)) + escText(sev) + "</td>" +
      (showCategory ? "<td>" + escText(catLabel) + "</td>" : "") +
      "<td>" + escText(f.tool || "—") + "</td>" +
      "<td>" + idCellHtml(f.id, f.category) + "</td>" +
      "<td class=\\"cell-title\\"><div>" + escText(f.title || "—") + "</div></td>" +
      "<td><code>" + escText(f.location || "—") + "</code></td>" +
      "<td>" + escText(f.fixed || "—") + "</td>" +
      "<td>" + escText(f.status || "—") + "</td>" +
      "</tr>";
  }}

  function renderFindings(findings, showCategory) {{
    // In display order: a row's data-finding-index points into it, which
    // the grouping and the sort make different from the report's order.
    visibleFindings = [];
    findingsHead.innerHTML = findingsHeadHtml(showCategory);
    if (!(findings || []).length) {{
      tbody.innerHTML = "";
      noResults.hidden = false;
      return;
    }}
    noResults.hidden = true;
    var groups = groupFindings(findings);
    var html = [];
    groups.forEach(function (g, gi) {{
      if (g.items.length === 1) {{
        html.push(findingRowHtml(g.items[0], visibleFindings.length, false, showCategory));
        visibleFindings.push(g.items[0]);
        return;
      }}
      var worstSev = g.items[0].severity || "unknown";
      var blockingCount = g.items.filter(function (it) {{ return it.status === "blocking"; }}).length;
      var groupId = "group-" + gi;
      var catLabel = CATEGORY_LABELS[g.category] || g.category || "—";
      html.push(
        "<tr class=\\"group-summary-row\\" data-group-toggle=\\"" + escText(groupId) +
        "\\" tabindex=\\"0\\" role=\\"button\\" aria-expanded=\\"false\\" aria-label=\\"Expand " +
        g.items.length + " findings for " + escText(g.location || "this item") + "\\">" +
        "<td>" + sevDot(escText(worstSev)) + escText(worstSev) + "</td>" +
        (showCategory ? "<td>" + escText(catLabel) + "</td>" : "") +
        "<td>" + escText(groupTools(g.items)) + "</td>" +
        "<td title=\\"" + escText(groupLabel(g)) + "\\"><span class=\\"group-caret\\">▸</span> <strong>" +
        escText(shortLabel(groupLabel(g))) + "</strong></td>" +
        "<td><span class=\\"group-stats\\"><span class=\\"group-count\\" title=\\"" + g.items.length + " findings\\">" +
        g.items.length + "</span>" + severityBarHtml(g.items) + "</span></td>" +
        "<td colspan=\\"2\\"><code>" + escText(g.location || "—") + "</code></td>" +
        "<td>" + (blockingCount ? blockingCount + " blocking" : "—") + "</td>" +
        "</tr>"
      );
      g.items.forEach(function (it) {{
        var idx = visibleFindings.length;
        html.push(findingRowHtml(it, idx, true, showCategory).replace(
          "data-finding-index=\\"" + idx + "\\"",
          "data-finding-index=\\"" + idx + "\\" data-group-member=\\"" + escText(groupId) + "\\""
        ));
        visibleFindings.push(it);
      }});
    }});
    tbody.innerHTML = html.join("");
  }}

  function toggleGroup(groupId, summaryEl) {{
    var expanded = summaryEl.getAttribute("aria-expanded") === "true";
    summaryEl.setAttribute("aria-expanded", String(!expanded));
    var members = tbody.querySelectorAll('[data-group-member="' + groupId + '"]');
    members.forEach(function (row) {{ row.hidden = expanded; }});
  }}

  function currentFindings() {{
    var run = RUNS[CURRENT_RUN];
    return run ? run.findings : [];
  }}

  // What the findings table shows: a tab ("all", or a category) and, on the
  // All tab only, a chart filter ({{key, value, label}} or null).
  var currentTab = "all";
  var currentFilter = null;

  // The categories of `findings`, known ones in this order, then any other.
  function tabCategories(findings) {{
    var present = [];
    findings.forEach(function (f) {{
      if (f.category && present.indexOf(f.category) === -1) present.push(f.category);
    }});
    return CATEGORY_TAB_ORDER.filter(function (c) {{ return present.indexOf(c) !== -1; }})
      .concat(present.filter(function (c) {{ return CATEGORY_TAB_ORDER.indexOf(c) === -1; }}));
  }}

  function renderTabs(findings) {{
    var tabs = [{{ key: "all", label: TAB_LABELS.all, count: findings.length }}].concat(
      tabCategories(findings).map(function (c) {{
        return {{ key: c, label: TAB_LABELS[c] || CATEGORY_LABELS[c] || c,
                  count: findings.filter(function (f) {{ return f.category === c; }}).length }};
      }}));
    var licenses = licenseRows();
    if (licenses && licenses.length) {{
      tabs.push({{ key: "licenses", label: TAB_LABELS.licenses, count: licenses.length, aside: true }});
    }}
    findingsTabs.innerHTML = tabs.map(function (t) {{
      var selected = t.key === currentTab;
      return "<button type=\\"button\\" class=\\"findings-tab" + (t.aside ? " tab-aside" : "") +
        "\\" role=\\"tab\\" data-findings-tab=\\"" +
        escText(t.key) + "\\" aria-selected=\\"" + selected + "\\">" +
        escText(t.label) + "<span class=\\"tab-count\\">(" + t.count + ")</span></button>";
    }}).join("");
  }}

  function matchesFilter(f, filter) {{
    if (filter.key === "severity") return f.severity === filter.value;
    if (filter.key === "category") return f.category === filter.value;
    if (filter.key === "status") return f.status === filter.value;
    if (filter.key === "fix") return f.category === "vuln" && fixKind(f) === filter.value;
    return true;
  }}

  // "blocking": a fix exists and the finding blocks (or would, or already
  // does on the target branch); "other": a fix exists, below the threshold
  // or excepted; "none": no fixed version published.
  function fixKind(f) {{
    if (!f.fixed) return "none";
    return ["blocking", "would-block", "existing"].indexOf(f.status) !== -1 ? "blocking" : "other";
  }}

  function licenseKind(c) {{
    if (c.verdict === "deny") return "deny";
    return (c.licenses || []).length ? "review" : "none";
  }}

  // The current run's components not allowed, denied first, then by name;
  // null for a report written before they were kept.
  function licenseRows() {{
    var run = RUNS[CURRENT_RUN];
    if (!run || !run.license_components) return null;
    return run.license_components.slice().sort(function (a, b) {{
      return LICENSE_KINDS.indexOf(licenseKind(a)) - LICENSE_KINDS.indexOf(licenseKind(b)) ||
        String(a.name).localeCompare(String(b.name));
    }});
  }}

  function renderLicenseTable(rows) {{
    visibleFindings = [];
    findingsHead.innerHTML = "<tr><th>Verdict</th><th>Component</th><th>Version</th><th>Licenses found</th><th>Location</th></tr>";
    noResults.hidden = rows.length > 0;
    tbody.innerHTML = rows.map(function (c) {{
      var kind = licenseKind(c);
      return "<tr><td><span class=\\"sev-dot\\" style=\\"background: var(--status-" + LICENSE_KIND_ROLES[kind] + ")\\"></span>" +
        escText(LICENSE_KIND_LABELS[kind]) + "</td>" +
        "<td><strong>" + escText(c.name || "?") + "</strong></td>" +
        "<td>" + escText(c.version || "—") + "</td>" +
        "<td class=\\"cell-title\\"><div>" + escText((c.licenses || []).join(", ") || "—") + "</div></td>" +
        "<td><code>" + escText(c.purl || "—") + "</code></td></tr>";
    }}).join("");
  }}

  // Re-renders the tabs, the table and its title from currentTab and
  // currentFilter: the one path for a tab, a filter, a run or a project.
  function refreshFindings() {{
    var all = currentFindings();
    var licenses = licenseRows();
    if (currentTab === "licenses") {{
      if (licenses && licenses.length) {{
        var rows = licenses.filter(function (c) {{
          return !currentFilter || licenseKind(c) === currentFilter.value;
        }});
        renderTabs(all);
        renderLicenseTable(rows);
        findingsTitle.textContent = "License components (" + rows.length + ")";
        findingsTitle.title = "Components whose license the gate didn't allow, denied first. " +
          "Every component and its verdict: licenses.md.";
        findingsSubtitle.hidden = !currentFilter;
        findingsSubtitle.textContent = currentFilter ? "Filtered by " + currentFilter.label + "." : "";
        clearBtn.hidden = !currentFilter;
        return;
      }}
      currentTab = "all";
    }}
    if (currentTab !== "all" && tabCategories(all).indexOf(currentTab) === -1) currentTab = "all";
    var shown = all.filter(function (f) {{
      return (currentTab === "all" || f.category === currentTab) &&
        (!currentFilter || matchesFilter(f, currentFilter));
    }});
    renderTabs(all);
    renderFindings(shown, currentTab === "all");
    findingsTitle.textContent = "Findings (" + shown.length + ")";
    // How to read the table: a tooltip on the title, not a line of text.
    findingsTitle.title = (currentTab === "all" ? "All findings" :
      (CATEGORY_LABELS[currentTab] || currentTab) + " findings") +
      " for the selected run, most severe first." +
      (currentTab === "all" ? " Click a chart above to filter." : "") +
      " Findings on the same component are grouped: click a group to expand it.";
    // Only a filter is worth a visible line: it hides findings.
    findingsSubtitle.hidden = !currentFilter;
    findingsSubtitle.textContent = currentFilter ? "Filtered by " + currentFilter.label + "." : "";
    clearBtn.hidden = !currentFilter;
  }}

  // A chart filter applies to the All tab, as before the tabs existed; a
  // License compliance one to the Licenses tab.
  function applyFilter(key, value, label) {{
    currentTab = key === "license" ? "licenses" : "all";
    currentFilter = {{ key: key, value: value, label: label }};
    refreshFindings();
    document.getElementById("findings-panel").scrollIntoView({{ behavior: "smooth", block: "nearest" }});
  }}

  function clearFilter() {{
    currentFilter = null;
    refreshFindings();
  }}

  function selectTab(tab) {{
    currentTab = tab;
    currentFilter = null;
    refreshFindings();
  }}

  function switchRun(runDir) {{
    var run = RUNS[runDir];
    if (!run) return;
    CURRENT_RUN = runDir;
    renderProjectDashboard();
  }}

  // Every run belonging to the same project as `run`, oldest first — same
  // grouping rule as the Python side (projects{{}} in build_html).
  function runsForProject(projectName) {{
    return Object.keys(RUNS)
      .filter(function (dir) {{ return RUNS[dir].project === projectName; }})
      .sort(function (a, b) {{
        var ta = RUNS[a].timestamp || "";
        var tb = RUNS[b].timestamp || "";
        return ta < tb ? -1 : ta > tb ? 1 : 0;
      }});
  }}

  // Full re-render of the project view for CURRENT_RUN: KPIs, the three bar
  // charts, the trend (if the project has more than one run), the findings
  // table (cleared of any filter), and the run-history table. Called on
  // project switch and on run switch — one code path, so they can't drift.
  function renderProjectDashboard() {{
    var run = RUNS[CURRENT_RUN];
    if (!run) return;
    var projectRuns = runsForProject(run.project);

    pageTitle.textContent = "Security dashboard — " + run.project;
    runMeta.textContent = (projectRuns.length > 1 ? "Run: " : "Latest run: ") +
      (run.timestamp || "—") + " — " + (run.failed ? "Failed" : "Passed") +
      " (" + run.blocking + " blocking) · " + projectRuns.length + " run(s) for this project";

    var totalFindings = Object.keys(run.by_severity || {{}}).reduce(
      function (sum, k) {{ return sum + run.by_severity[k]; }}, 0);
    var lic = run.licenses || {{}};
    var audited = !run.failed && run.would_block;
    kpiRow.innerHTML =
      statTileHtml("Status", run.failed ? "Failed" : (audited ? "Passed (not enforced)" : "Passed"),
                    run.failed ? "critical" : (audited ? "warning" : "good")) +
      (audited ? statTileHtml("Would block (not enforced)", run.would_block, "warning",
                              "status", "would-block") : "") +
      (run.existing ? statTileHtml("Already on target branch", run.existing, "warning",
                                   "status", "existing") : "") +
      statTileHtml("Blocking findings", run.blocking, run.blocking ? "critical" : "good",
                    run.blocking ? "status" : "", "blocking") +
      statTileHtml("Total findings", totalFindings, "") +
      statTileHtml("Denied licenses", lic.deny || 0, lic.deny ? "critical" : "good");

    var sevItems = SEVERITY_ORDER.filter(function (s) {{ return (run.by_severity || {{}})[s]; }})
      .map(function (s) {{
        return {{ label: s.charAt(0).toUpperCase() + s.slice(1), value: run.by_severity[s],
                  role: SEVERITY_STATUS[s], filterVal: s }};
      }});
    renderBarChart(document.querySelector("#chart-severity .chart-svg"), sevItems, "severity");

    var catItems = Object.keys(run.by_category || {{}})
      .filter(function (c) {{ return run.by_category[c]; }})
      .map(function (c) {{ return {{ key: c, label: CATEGORY_LABELS[c] || c, value: run.by_category[c] }}; }})
      .sort(function (a, b) {{ return b.value - a.value; }})
      .map(function (it) {{
        return {{ label: it.label, value: it.value, role: CATEGORY_ROLES[it.key] || "warning", filterVal: it.key }};
      }});
    renderBarChart(document.querySelector("#chart-category .chart-svg"), catItems, "category");

    var licRows = licenseRows();
    var licItems;
    if (licRows) {{
      // Review split by what to do: a license to review, or none found.
      var kinds = {{ deny: 0, review: 0, none: 0 }};
      licRows.forEach(function (c) {{ kinds[licenseKind(c)]++; }});
      licItems = (lic.allow ? [{{ label: LICENSE_LABELS.allow, value: lic.allow, role: LICENSE_ROLES.allow, filterVal: "" }}] : [])
        .concat(["review", "none", "deny"].filter(function (k) {{ return kinds[k]; }}).map(function (k) {{
          return {{ label: LICENSE_KIND_LABELS[k], value: kinds[k], role: LICENSE_KIND_ROLES[k], filterVal: k }};
        }}));
    }} else {{
      licItems = ["allow", "review", "deny"].filter(function (k) {{ return lic[k]; }})
        .map(function (k) {{ return {{ label: LICENSE_LABELS[k], value: lic[k], role: LICENSE_ROLES[k], filterVal: k }}; }});
    }}
    renderBarChart(document.querySelector("#chart-licenses .chart-svg"), licItems, licRows ? "license" : "");

    var fixCounts = {{ blocking: 0, other: 0, none: 0 }};
    (run.findings || []).forEach(function (f) {{ if (f.category === "vuln") fixCounts[fixKind(f)]++; }});
    var fixItems = FIX_KINDS.filter(function (k) {{ return fixCounts[k]; }}).map(function (k) {{
      return {{ label: FIX_LABELS[k], value: fixCounts[k], role: FIX_ROLES[k], filterVal: k }};
    }});
    renderBarChart(document.querySelector("#chart-fix .chart-svg"), fixItems, "fix");

    var trendChart = document.getElementById("chart-trend");
    if (projectRuns.length >= 2) {{
      trendChart.hidden = false;
      document.getElementById("chart-trend-title").textContent =
        "Blocking findings over time (" + projectRuns.length + " runs)";
      var points = projectRuns.map(function (dir) {{
        return {{ label: RUNS[dir].timestamp_short, value: RUNS[dir].blocking, runDir: dir }};
      }});
      renderTrendChart(trendChart.querySelector(".chart-svg"), points);
    }} else {{
      trendChart.hidden = true;
    }}

    clearFilter();

    if (projectRuns.length > 1) {{
      runHistorySection.hidden = false;
      runHistoryBody.innerHTML = projectRuns.slice().reverse().map(function (dir) {{
        var r = RUNS[dir];
        var isCurrent = dir === CURRENT_RUN;
        var total = Object.keys(r.by_severity || {{}}).reduce(function (s, k) {{ return s + r.by_severity[k]; }}, 0);
        var rowCls = isCurrent ? "run-current" : "run-row-clickable";
        var attrs = isCurrent ? "" :
          ' tabindex="0" role="button" data-filter-key="run" data-filter-value="' + escText(dir) +
          '" data-filter-label="' + escText(r.timestamp_short) + '"';
        return '<tr class="' + rowCls + '"' + attrs + '>' +
          "<td>" + escText(r.timestamp || "—") + "</td><td>" + (r.failed ? "Failed" : "Passed") +
          "</td><td>" + r.blocking + "</td><td>" + total + "</td></tr>";
      }}).join("");
    }} else {{
      runHistorySection.hidden = true;
    }}
  }}

  function renderPortfolio() {{
    portfolioBody.innerHTML = PORTFOLIO.map(function (p) {{
      return '<tr class="run-row-clickable" tabindex="0" role="button" data-open-project="' +
        escText(p.name) + '" data-filter-value="' + escText(p.runDir) +
        '" aria-label="Open project ' + escText(p.name) + '">' +
        "<td>" + escText(p.name) + "</td>" +
        "<td>" + (p.failed ? "Failed" : "Passed") + "</td>" +
        "<td>" + escText(p.timestamp || "—") + "</td>" +
        "<td>" + p.blocking + "</td>" +
        "<td>" + p.totalFindings + "</td>" +
        "<td>" + p.deniedLicenses + "</td>" +
        "<td>" + p.runCount + "</td></tr>";
    }}).join("");
  }}

  function switchProject(runDir) {{
    if (!RUNS[runDir]) return;
    CURRENT_RUN = runDir;
    portfolioView.hidden = true;
    projectView.hidden = false;
    pageMeta.hidden = true;
    renderProjectDashboard();
    window.scrollTo({{ top: 0, behavior: "instant" }});
  }}

  function backToPortfolio() {{
    projectView.hidden = true;
    portfolioView.hidden = false;
    pageMeta.hidden = false;
    pageTitle.textContent = "Security dashboard";
    window.scrollTo({{ top: 0, behavior: "instant" }});
  }}

  document.getElementById("back-to-portfolio").addEventListener("click", backToPortfolio);

  // --- Finding detail modal --------------------------------------------
  // Opens on row click/Enter/Space; shows every field aggregate_report.py
  // collected for that finding, not just the compact table columns.
  var modal = document.getElementById("finding-modal");
  var modalTitle = document.getElementById("modal-title");
  var modalBadges = document.getElementById("modal-badges");
  var modalFields = document.getElementById("modal-fields");
  var modalClose = document.getElementById("modal-close");
  var lastFocusedEl = null;

  var SEVERITY_ROLE = {{ critical: "critical", high: "serious", medium: "warning", low: "good" }};
  var STATUS_LABEL = {{
    blocking: "Blocking — fails the gate",
    "would-block": "Would block in enforce mode (not enforced here)",
    existing: "Would block, but already on the target branch (not brought by this merge request)",
    "sans-correctif": "No fix available yet (tracked, non-blocking)",
    exception: "Covered by a policy exception",
    info: "Below the blocking threshold"
  }};

  function fieldRow(label, value, opts) {{
    opts = opts || {{}};
    var dd = document.createElement("dd");
    var hasValue = value != null && value !== "";
    if (opts.link && hasValue) {{
      var a = document.createElement("a");
      a.href = opts.link;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.className = "advisory-link";
      var codeEl2 = document.createElement("code");
      codeEl2.textContent = String(value);
      a.appendChild(codeEl2);
      dd.appendChild(a);
    }} else if (opts.code) {{
      var codeEl = document.createElement("code");
      codeEl.textContent = hasValue ? String(value) : "—";
      dd.appendChild(codeEl);
    }} else {{
      dd.textContent = hasValue ? String(value) : "—";
      if (!hasValue) dd.className = "dd-muted";
    }}
    var dt = document.createElement("dt");
    dt.textContent = label;
    modalFields.appendChild(dt);
    modalFields.appendChild(dd);
  }}

  function openFindingDetail(finding) {{
    if (!finding) return;
    lastFocusedEl = document.activeElement;
    modalTitle.textContent = finding.title || "Untitled finding";

    var sev = finding.severity || "low";
    var role = SEVERITY_ROLE[sev] || "good";
    modalBadges.innerHTML = "";
    var sevBadge = document.createElement("span");
    sevBadge.className = "badge badge-" + role;
    sevBadge.textContent = sev.charAt(0).toUpperCase() + sev.slice(1);
    modalBadges.appendChild(sevBadge);

    var catBadge = document.createElement("span");
    catBadge.className = "badge";
    catBadge.textContent = CATEGORY_LABELS[finding.category] || finding.category || "Uncategorized";
    modalBadges.appendChild(catBadge);

    if (finding.status) {{
      var statusRole = finding.status === "blocking" ? "critical" : "good";
      var statusBadge = document.createElement("span");
      statusBadge.className = "badge badge-" + statusRole;
      statusBadge.textContent = finding.status;
      modalBadges.appendChild(statusBadge);
    }}

    modalFields.innerHTML = "";
    fieldRow("Tool", finding.tool);
    fieldRow("ID", finding.id, {{ code: true, link: advisoryUrl(finding.id) }});
    fieldRow("Location", finding.location, {{ code: true }});
    fieldRow("Category", CATEGORY_LABELS[finding.category] || finding.category);
    fieldRow("Severity", sev);
    fieldRow("Fix available", finding.fixed);
    fieldRow("Gate status", STATUS_LABEL[finding.status] || finding.status);
    // The advisory's summary, or a rule's whole message when the title
    // shortens it.
    if (finding.description) fieldRow("Description", finding.description);

    renderCodePreview(finding.context);

    modal.hidden = false;
    modalClose.focus();
    document.addEventListener("keydown", onModalKeydown);
  }}

  var codePreviewEl = document.getElementById("modal-code-preview");

  function renderCodePreview(context) {{
    codePreviewEl.innerHTML = "";
    if (!context || !context.lines || !context.lines.length) {{
      codePreviewEl.hidden = true;
      return;
    }}
    codePreviewEl.hidden = false;
    codePreviewEl.className = "code-preview";

    var header = document.createElement("div");
    header.className = "code-preview-header";
    header.textContent = "Context — " + (context.path || "file");
    codePreviewEl.appendChild(header);

    var pre = document.createElement("pre");
    context.lines.forEach(function (line) {{
      var row = document.createElement("div");
      row.className = "code-preview-line" + (line.highlight ? " highlight" : "");
      var lineno = document.createElement("span");
      lineno.className = "code-preview-lineno";
      lineno.textContent = String(line.number);
      var text = document.createElement("span");
      text.className = "code-preview-text";
      text.textContent = line.text;
      row.appendChild(lineno);
      row.appendChild(text);
      pre.appendChild(row);
    }});
    codePreviewEl.appendChild(pre);

    var note = document.createElement("div");
    note.className = "code-preview-note";
    note.textContent = "The secret itself is redacted (█). Only its position on the highlighted line is shown.";
    codePreviewEl.appendChild(note);
  }}

  function closeFindingDetail() {{
    modal.hidden = true;
    document.removeEventListener("keydown", onModalKeydown);
    if (lastFocusedEl && typeof lastFocusedEl.focus === "function") lastFocusedEl.focus();
  }}

  function onModalKeydown(evt) {{
    if (evt.key === "Escape") closeFindingDetail();
  }}

  modalClose.addEventListener("click", closeFindingDetail);
  modal.addEventListener("click", function (evt) {{
    if (evt.target === modal) closeFindingDetail();
  }});

  clearBtn.addEventListener("click", clearFilter);

  document.addEventListener("click", function (evt) {{
    var tabEl = evt.target.closest("[data-findings-tab]");
    if (tabEl) {{
      selectTab(tabEl.getAttribute("data-findings-tab"));
      return;
    }}
    var projectRow = evt.target.closest("[data-open-project]");
    if (projectRow) {{
      switchProject(projectRow.getAttribute("data-filter-value"));
      return;
    }}
    var groupRow = evt.target.closest("[data-group-toggle]");
    if (groupRow) {{
      toggleGroup(groupRow.getAttribute("data-group-toggle"), groupRow);
      return;
    }}
    var findingRow = evt.target.closest("[data-finding-index]");
    if (findingRow) {{
      var idx = parseInt(findingRow.getAttribute("data-finding-index"), 10);
      openFindingDetail(visibleFindings[idx]);
      return;
    }}
    var el = evt.target.closest("[data-filter-key]");
    if (!el) return;
    handleActivate(el);
  }});
  document.addEventListener("keydown", function (evt) {{
    if (evt.key !== "Enter" && evt.key !== " ") return;
    var projectRow = evt.target.closest("[data-open-project]");
    if (projectRow) {{
      evt.preventDefault();
      switchProject(projectRow.getAttribute("data-filter-value"));
      return;
    }}
    var groupRow = evt.target.closest("[data-group-toggle]");
    if (groupRow) {{
      evt.preventDefault();
      toggleGroup(groupRow.getAttribute("data-group-toggle"), groupRow);
      return;
    }}
    var findingRow = evt.target.closest("[data-finding-index]");
    if (findingRow) {{
      evt.preventDefault();
      var idx = parseInt(findingRow.getAttribute("data-finding-index"), 10);
      openFindingDetail(visibleFindings[idx]);
      return;
    }}
    var el = evt.target.closest("[data-filter-key]");
    if (!el) return;
    evt.preventDefault();
    handleActivate(el);
  }});

  function handleActivate(el) {{
    var key = el.getAttribute("data-filter-key");
    var value = el.getAttribute("data-filter-value");
    var label = el.getAttribute("data-filter-label") || value;
    if (key === "run") {{
      switchRun(value, label);
    }} else {{
      applyFilter(key, value, label);
    }}
  }}

  // Initial screen: the portfolio when more than one project was found,
  // straight to that project's dashboard otherwise (a single-project run
  // has nothing to pick from — skip the extra click).
  renderPortfolio();
  if (PORTFOLIO.length > 1) {{
    portfolioView.hidden = false;
    projectView.hidden = true;
  }} else {{
    switchProject(DEFAULT_RUN);
  }}
}})();
</script>
</body>
</html>
'''


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reports-root", required=True, type=Path,
                     help="Root folder containing <project>/<timestamp>/ sub-folders "
                          "(one folder per analyzed project), or a single report folder.")
    ap.add_argument("--project", default=None,
                     help="Project to open by default when the dashboard loads (the "
                          "sub-folder name under --reports-root). All projects found "
                          "are always included — this only picks the initial view. "
                          "Defaults to whichever project has the most recent run.")
    ap.add_argument("--output", type=Path, default=None,
                     help="Output HTML file (default: <reports-root>/dashboard.html)")
    args = ap.parse_args()

    if not args.reports_root.is_dir():
        sys.exit(f"Folder not found: {args.reports_root}")

    all_runs = discover_runs(args.reports_root)
    if not all_runs:
        sys.exit(f"No security-report.json found under {args.reports_root} "
                  "(neither directly, nor in a sub-folder).")

    project_names = sorted({r["name"] for r in all_runs})

    if args.project:
        if args.project not in project_names:
            sys.exit(f"Unknown project {args.project!r}. Available: {', '.join(project_names)}")
        default_project = args.project
    else:
        # Default: the project of the most recent run overall.
        default_project = all_runs[-1]["name"]

    output = args.output or (args.reports_root / "dashboard.html")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(build_html(all_runs, args.reports_root, default_project), encoding="utf-8")

    print(f"Dashboard generated: {output}  "
          f"({len(project_names)} project(s), {len(all_runs)} run(s) total)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
