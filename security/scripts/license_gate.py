#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""
License compliance check from a CycloneDX SBOM.

Reads the SBOM produced by Syft, evaluates each component against the policy
defined in security/policy-global.yml, and exits with code 1 if the policy is violated.

Usage:
    python license_gate.py --sbom sbom.cdx.json --policy policy-global.yml \
                           --output-dir security-reports
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

from license_ids import SPDX_EXCEPTION_IDS, license_key, normalize
from policy import effective_policy

# Always output UTF-8: the report contains emoji (✅⚠️⛔), and a Windows
# terminal in cp1252 would otherwise crash on a bare print().
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

ALLOW, REVIEW, DENY = "allow", "review", "deny"
RANK = {ALLOW: 0, REVIEW: 1, DENY: 2}
BY_RANK = {v: k for k, v in RANK.items()}

# SBOM entries that aren't packages, so have no license to check: the base
# OS of an image, and `file` (the scanned directory `.`, Syft's metadata
# component carried over by the merge, and each manifest Syft or cdxgen
# read: pom.xml, go.mod, requirements.txt...). Counted in the report as
# skipped, never given the policy's `unknown` verdict.
NON_PACKAGE_TYPES = ("operating-system", "file")


# --------------------------------------------------------------------------- #
#  Evaluating SPDX expressions
# --------------------------------------------------------------------------- #
def _split_top_level(expr: str, operator: str) -> list[str]:
    """Splits on an operator, ignoring anything inside parentheses. Case-
    sensitive, as SPDX operators are: `or` / `and` in a license name ("MIT
    License or Later") are words, not operators."""
    parts, depth, current, i = [], 0, "", 0
    token = f" {operator} "
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth == 0 and expr[i:i + len(token)] == token:
            parts.append(current)
            current = ""
            i += len(token)
            continue
        current += ch
        i += 1
    parts.append(current)
    return [p.strip() for p in parts if p.strip()]


def _strip_parens(expr: str) -> str:
    expr = expr.strip()
    while expr.startswith("(") and expr.endswith(")"):
        depth = 0
        for i, ch in enumerate(expr):
            depth += (ch == "(") - (ch == ")")
            if depth == 0 and i < len(expr) - 1:
                return expr  # the parentheses don't cover everything
        expr = expr[1:-1].strip()
    return expr


def evaluate(expr: str, table: dict[str, str], unknown: str,
             seen: set[str]) -> str:
    """
    Returns the verdict for an SPDX expression.
      - The whole label is looked up first: a listed license name holding
        an operator word is a license, not an expression.
      - Otherwise it's split on the SPDX operators (uppercase only):
          OR  → keeps the most permissive option (choice left to the consumer)
          AND → keeps the most restrictive one (both apply)
      - `X WITH Y` not listed as-is falls back to X only when Y is an SPDX
        exception (extra permissions); a restricting clause (Commons-Clause,
        ...) or an unknown one isn't dropped.
    A label left unmatched gets `unknown` and is added to `seen`, whole —
    never as fragments of a name split on a word.
    """
    expr = _strip_parens(expr)
    if not expr:
        seen.add("(empty)")
        return unknown

    verdict = table.get(license_key(expr))
    if verdict:
        return verdict

    or_parts = _split_top_level(expr, "OR")
    if len(or_parts) > 1:
        return BY_RANK[min(RANK[evaluate(p, table, unknown, seen)] for p in or_parts)]

    and_parts = _split_top_level(expr, "AND")
    if len(and_parts) > 1:
        return BY_RANK[max(RANK[evaluate(p, table, unknown, seen)] for p in and_parts)]

    # Leaf, not listed as-is (looked up above)
    leaf = normalize(expr)
    base, sep, exception = leaf.partition(" WITH ")
    if sep and exception.strip().lower() in SPDX_EXCEPTION_IDS:
        verdict = table.get(license_key(base))
        if verdict:
            return verdict
    seen.add(leaf)
    return unknown


# --------------------------------------------------------------------------- #
#  Reading the SBOM
# --------------------------------------------------------------------------- #
def iter_components(node: dict[str, Any]):
    for comp in node.get("components", []) or []:
        yield comp
        yield from iter_components(comp)


def licenses_of(comp: dict[str, Any]) -> list[str]:
    """
    Extracts the license expressions of a CycloneDX component.
    Several entries in the `licenses` array are treated as a choice (OR):
    that's the dominant case in practice (`MIT OR Apache-2.0` on almost all
    Rust crates). Manually check the multi-license components flagged in the
    report if your context requires the AND interpretation.
    """
    out = []
    for entry in comp.get("licenses", []) or []:
        if "expression" in entry:
            out.append(entry["expression"])
        elif "license" in entry:
            lic = entry["license"]
            value = lic.get("id") or lic.get("name")
            if value:
                out.append(value)
    return out


def matches_exception(comp: dict[str, Any], pattern: str) -> bool:
    purl = comp.get("purl", "") or ""
    name = comp.get("name", "") or ""
    version = comp.get("version", "") or ""
    return pattern in (purl, name, f"{name}@{version}")


# --------------------------------------------------------------------------- #
#  Report
# --------------------------------------------------------------------------- #
def render_markdown(results: list[dict], counts: dict[str, int],
                    unknown_labels: set[str], failed: bool,
                    model: str, would_fail: bool = False,
                    skipped: dict[str, int] | None = None) -> str:
    lines = [
        "# License compliance",
        "",
        f"Distribution model in use: **{model}**",
        "",
        f"| Verdict | Components |",
        f"|---|---|",
        f"| ✅ Allowed | {counts[ALLOW]} |",
        f"| ⚠️ To review | {counts[REVIEW]} |",
        f"| ⛔ Denied | {counts[DENY]} |",
        f"| 🟰 Exception | {counts['exception']} |",
        "",
    ]
    if skipped:
        detail = ", ".join(f"{n} {kind}" for kind, n in sorted(skipped.items()))
        lines += [f"Not checked: {sum(skipped.values())} SBOM entries that aren't "
                  f"packages ({detail}).", ""]

    for verdict, title, icon in ((DENY, "Denied", "⛔"), (REVIEW, "To review", "⚠️")):
        rows = [r for r in results if r["verdict"] == verdict]
        if not rows:
            continue
        lines += [f"## {icon} {title} ({len(rows)})", "",
                  "| Component | Version | License(s) |", "|---|---|---|"]
        for r in sorted(rows, key=lambda x: x["name"])[:200]:
            lic = ", ".join(r["licenses"]) or "_not declared_"
            lines.append(f"| `{r['name']}` | {r['version']} | {lic} |")
        if len(rows) > 200:
            lines.append(f"| … | | _{len(rows) - 200} more, see the JSON_ |")
        lines.append("")

    if unknown_labels:
        lines += ["## Unclassified licenses encountered", "",
                  "To be decided, then added to the organization's license lists (policy-licenses.yml) "
                  "or to the project's policy:", ""]
        lines += [f"- `{u}`" for u in sorted(unknown_labels)[:60]]
        lines.append("")

    if would_fail and not failed:
        lines.append("**Result: ⚠️ would fail in enforce mode (licenses in audit mode)**")
    else:
        lines.append("**Result: " + ("❌ FAILED" if failed else "✅ OK") + "**")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sbom", required=True, type=Path)
    ap.add_argument("--policy", required=True, type=Path)
    ap.add_argument("--output-dir", default=Path("security-reports"), type=Path)
    args = ap.parse_args()

    try:
        policy = effective_policy(args.policy)
    except (OSError, ValueError) as exc:  # unreadable policy, missing lists_file, bad mode
        print(f"::error:: {exc}", file=sys.stderr)
        return 2
    lic_policy = policy.get("licenses", {}) or {}
    model = (policy.get("meta", {}) or {}).get("distribution_model", "undefined")

    table: dict[str, str] = {}
    for verdict in (ALLOW, REVIEW, DENY):
        for item in lic_policy.get(verdict, []) or []:
            table[license_key(item)] = verdict

    unknown_verdict = lic_policy.get("unknown", REVIEW)
    if unknown_verdict not in RANK:
        unknown_verdict = REVIEW

    if not args.sbom.exists():
        print(f"::error:: SBOM not found: {args.sbom}", file=sys.stderr)
        return 2
    sbom = json.loads(args.sbom.read_text(encoding="utf-8"))

    # An exception WITHOUT a valid expiration date (missing, or wrongly
    # typed — e.g. `expires: "2027-01-01"` in quotes, which PyYAML keeps
    # as a str rather than a date) is rejected, not kept active
    # indefinitely. This is the behavior documented in the README
    # ("Without expires, the script rejects it") — without this
    # safeguard, a YAML typo would silently make an exception permanent.
    today = date.today()
    exceptions = []
    for exc in lic_policy.get("exceptions", []) or []:
        exp = exc.get("expires")
        if isinstance(exp, datetime):
            exp = exp.date()
        if not isinstance(exp, date):
            print(f"::warning:: Exception with no valid expiration date for "
                  f"{exc.get('package')} — ignored (expected: an unquoted "
                  f"YAML date, e.g. expires: 2027-01-01).")
            continue
        if exp < today:
            print(f"::warning:: Exception expired on {exp} for "
                  f"{exc.get('package')} — it is blocking again.")
            continue
        exceptions.append(exc)

    results: list[dict] = []
    counts = {ALLOW: 0, REVIEW: 0, DENY: 0, "exception": 0}
    unknown_labels: set[str] = set()
    skipped: dict[str, int] = {}

    for comp in iter_components(sbom):
        if comp.get("type") in NON_PACKAGE_TYPES:
            skipped[comp["type"]] = skipped.get(comp["type"], 0) + 1
            continue
        declared = licenses_of(comp)
        seen: set[str] = set()

        if declared:
            expr = declared[0] if len(declared) == 1 else \
                " OR ".join(f"({d})" for d in declared)
            verdict = evaluate(expr, table, unknown_verdict, seen)
        else:
            verdict = unknown_verdict
            seen.add("(no license declared)")

        exempted = any(matches_exception(comp, e.get("package", ""))
                       for e in exceptions)
        if exempted and verdict != ALLOW:
            counts["exception"] += 1
            verdict = ALLOW
        else:
            unknown_labels |= seen

        counts[verdict] += 1
        results.append({
            "name": comp.get("name", "?"),
            "version": comp.get("version", ""),
            "purl": comp.get("purl", ""),
            "licenses": declared,
            "verdict": verdict,
            "exempted": exempted,
        })

    would_fail = (lic_policy.get("fail_on_deny", True) and counts[DENY] > 0) or \
                 (lic_policy.get("fail_on_review", False) and counts[REVIEW] > 0)
    # Audit mode (see policy.py): same verdict, reported, never blocking.
    mode = lic_policy.get("mode", "enforce")
    failed = would_fail and mode == "enforce"

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "licenses.json").write_text(
        json.dumps({"summary": counts, "failed": failed, "would_fail": would_fail,
                    "mode": mode, "distribution_model": model,
                    "unclassified": sorted(unknown_labels),
                    "skipped": skipped,
                    "components": results}, indent=2, ensure_ascii=False),
        encoding="utf-8")
    md = render_markdown(results, counts, unknown_labels, failed, model, would_fail, skipped)
    (args.output_dir / "licenses.md").write_text(md, encoding="utf-8")

    print(md)
    if failed:
        print("\n::error:: License policy violated.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
