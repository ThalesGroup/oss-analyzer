#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""
Draft of complete license lists, for legal review — every SPDX identifier
classified allow / review / deny.

Sources, by precedence:
  1. the policy's own common lists (licenses.allow / review / deny): a
     decision already taken always wins;
  2. the ScanCode LicenseDB category of the license, mapped to a verdict
     (CATEGORY_VERDICT below);
  3. neither: the policy's `licenses.unknown` verdict.
The policy's by_distribution_model rules, if any, are not applied: the
catalog covers the common lists (the organization base has no model rules).

The report lists what legal has to look at: the policy's choices that
disagree with ScanCode, the policy entries that aren't SPDX identifiers
and look like a mistake (with the ScanCode LicenseRef key to use instead,
when there is one), and optionally the labels gate runs left unclassified
(`--gate-report`). The non-SPDX entries written on purpose — LicenseRef
keys of live ScanCode licenses, and the names of licenses with no SPDX
identifier listed in the lists file's names group (license_lists.py) —
are only counted.

Nothing is written into the policy: the YAML produced is meant to be
reviewed, then copied into it.

Usage:
    python build_license_catalog.py --policy security/policy-global.yml \
        [--gate-report security-reports/licenses.json ...] \
        [--spdx-licenses licenses.json --spdx-exceptions exceptions.json \
         --scancode index.json] \
        --output-dir security-reports/license-catalog
Each source is a URL (default: the upstream one) or a local file, for
offline runs.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import sys
from collections import Counter
from itertools import takewhile
from pathlib import Path

import yaml

from license_ids import license_key
from license_sources import SCANCODE_URL, SPDX_EXCEPTIONS_URL, SPDX_LICENSES_URL, fetch_json
from license_lists import NAMES_GROUP, read_groups
from policy import LICENSE_VERDICTS, lists_file_path, load_policy

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

# ScanCode category → draft verdict. A starting point, not a legal opinion:
# the policy's own lists override it, and its disagreements are reported.
CATEGORY_VERDICT = {
    "Permissive": "allow",
    "Public Domain": "allow",
    "Copyleft Limited": "review",
    "Free Restricted": "review",
    "Patent License": "review",
    "Unstated License": "review",
    "CLA": "review",
    "Copyleft": "deny",
    "Non-Commercial": "deny",
    "Source-available": "deny",
    "Proprietary Free": "deny",
    "Commercial": "deny",
}


# --------------------------------------------------------------------------- #
#  Building the catalog
# --------------------------------------------------------------------------- #
def scancode_index(scancode: list[dict]) -> dict[str, dict]:
    """SPDX identifier (lowercased, deprecated ones included) → ScanCode entry."""
    out: dict[str, dict] = {}
    for entry in scancode:
        if entry.get("is_deprecated"):
            continue
        keys = [entry.get("spdx_license_key")] + list(entry.get("other_spdx_license_keys") or [])
        for key in filter(None, keys):
            out.setdefault(key.lower(), entry)
    return out


def policy_verdicts(lic_policy: dict) -> dict[str, tuple[str, str]]:
    """license key → (verdict, the label as written in the policy)."""
    out = {}
    for verdict in LICENSE_VERDICTS:
        for item in lic_policy.get(verdict) or []:
            out[license_key(item)] = (verdict, str(item))
    return out


def suggestion_index(scancode: list[dict]) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Built once for suggest_licenseref: (ScanCode key or SPDX ref, both
    lowercased → SPDX ref; (ScanCode key, SPDX ref) sorted, for prefix
    lookups). Deprecated keys carry no SPDX ref (e.g. `proprietary`,
    replaced by `proprietary-license`): only live ones are worth suggesting."""
    exact: dict[str, str] = {}
    by_key: list[tuple[str, str]] = []
    for e in scancode:
        ref = e.get("spdx_license_key")
        if not ref or e.get("is_deprecated"):
            continue
        key = (e.get("license_key") or "").lower()
        exact.setdefault(key, ref)
        exact.setdefault(ref.lower(), ref)
        by_key.append((key, ref))
    return exact, sorted(by_key)


def suggest_licenseref(label: str, index: tuple[dict[str, str], list[tuple[str, str]]]) -> str | None:
    """The ScanCode LicenseRef key a non-SPDX policy entry probably means."""
    exact, by_key = index
    low = label.lower()
    stem = low.removeprefix("licenseref-scancode-")
    if stem in exact or low in exact:
        return exact.get(stem) or exact[low]
    # First ScanCode key starting with `<stem>-`, in sorted order.
    prefix = stem + "-"
    i = bisect.bisect_left(by_key, (prefix, ""))
    refs = [ref for _key, ref in takewhile(lambda kr: kr[0].startswith(prefix), by_key[i:])]
    return min(refs) if refs else None


def build_catalog(spdx_licenses: list[dict], spdx_exceptions: list[dict],
                  scancode: list[dict], lic_policy: dict,
                  listed_names: frozenset[str] = frozenset()) -> dict:
    """`listed_names`: license keys of the names of licenses with no SPDX
    identifier the lists file holds (listed_names() below), expected in
    the policy."""
    by_spdx = scancode_index(scancode)
    decided = policy_verdicts(lic_policy)
    unknown = lic_policy.get("unknown", "review")
    if unknown not in LICENSE_VERDICTS:
        unknown = "review"

    entries, disagreements = [], []
    spdx_keys = set()
    for lic in sorted(spdx_licenses, key=lambda x: x["licenseId"].lower()):
        spdx_id = lic["licenseId"]
        spdx_keys.add(spdx_id.lower())
        sc = by_spdx.get(spdx_id.lower())
        category = sc.get("category") if sc else None
        proposed = CATEGORY_VERDICT.get(category) if category else None
        if license_key(spdx_id) in decided:
            verdict, source = decided[license_key(spdx_id)][0], "policy"
            if proposed and proposed != verdict:
                disagreements.append({"id": spdx_id, "policy": verdict,
                                      "scancode": proposed, "category": category})
        elif proposed:
            verdict, source = proposed, "scancode"
        else:
            verdict, source = unknown, "unclassified"
        entries.append({"id": spdx_id, "verdict": verdict, "source": source,
                        "category": category,
                        "deprecated": bool(lic.get("isDeprecatedLicenseId")),
                        "osi": bool(lic.get("isOsiApproved")),
                        "fsf": bool(lic.get("isFsfLibre"))})

    exception_ids = {e["licenseExceptionId"].lower() for e in spdx_exceptions}
    index = suggestion_index(scancode)
    live_refs = {e["spdx_license_key"].lower() for e in scancode
                 if not e.get("is_deprecated")
                 and (e.get("spdx_license_key") or "").lower().startswith("licenseref-")}
    # Policy entries the SPDX list doesn't know: `X WITH Y` with SPDX parts
    # are fine (kept as-is in the draft). So are, but counted apart
    # (not_spdx_expected) rather than reported, the LicenseRef keys of live
    # ScanCode licenses and the listed names of licenses with no SPDX
    # identifier: both are written on purpose. Anything else is reported
    # (not_spdx): a misspelled SPDX ID, a stale ScanCode key... WITH is
    # matched whatever its case here: the label is listed whole, and the
    # gate looks a listed label up whole before anything else.
    with_entries, not_spdx, not_spdx_expected = [], [], []
    for key, (verdict, label) in sorted(decided.items()):
        parts = re.split(r"\s+WITH\s+", label, maxsplit=1, flags=re.IGNORECASE)
        if len(parts) == 2 and license_key(parts[0]) in spdx_keys and parts[1].lower() in exception_ids:
            with_entries.append({"id": label, "verdict": verdict, "source": "policy"})
        elif key in spdx_keys:
            continue
        elif label.lower() in live_refs:
            not_spdx_expected.append({"id": label, "verdict": verdict, "reason": "scancode-key"})
        elif key in listed_names:
            not_spdx_expected.append({"id": label, "verdict": verdict, "reason": "listed-name"})
        else:
            not_spdx.append({"id": label, "verdict": verdict,
                             "suggestion": suggest_licenseref(label, index)})

    # Written as such in the policy, not merely matched through normalization.
    deprecated_ids = {e["id"].lower(): e["id"] for e in entries if e["deprecated"]}
    deprecated_in_policy = sorted(deprecated_ids[label.lower()] for _v, label in decided.values()
                                  if label.lower() in deprecated_ids)
    return {"entries": entries, "with_entries": with_entries,
            "disagreements": disagreements, "not_spdx": not_spdx,
            "not_spdx_expected": not_spdx_expected,
            "deprecated_in_policy": deprecated_in_policy}


def listed_names(policy_path: Path) -> frozenset[str]:
    """License keys of the entries the policy's lists file holds under
    the "Names of licenses with no SPDX identifier" group (license_lists.py);
    empty when the policy has no lists file or it has no group comments."""
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    lists_path = lists_file_path(policy_path, policy)
    if lists_path is None:
        return frozenset()
    groups = read_groups(lists_path.read_text(encoding="utf-8"))
    return frozenset(license_key(label) for label, group in groups.items() if group == NAMES_GROUP)


def seen_labels(reports: list[Path]) -> Counter:
    """Labels the license gate left unclassified, across its licenses.json reports."""
    seen: Counter = Counter()
    for path in reports:
        data = json.loads(path.read_text(encoding="utf-8"))
        seen.update(data.get("unclassified") or [])
    return seen


# --------------------------------------------------------------------------- #
#  Output
# --------------------------------------------------------------------------- #
def render_yaml(catalog: dict, versions: dict[str, str]) -> str:
    lines = [
        "# Draft license lists — generated by build_license_catalog.py, NOT a",
        "# validated policy: review it with legal before copying it into",
        "# the policy. The comment on each line gives where its verdict comes",
        "# from: the policy itself, a ScanCode category, or neither.",
        f"# SPDX License List {versions['spdx']}, ScanCode LicenseDB {versions['scancode']}.",
        "licenses:",
    ]
    rows = catalog["entries"] + catalog["with_entries"] + [
        {"id": e["id"], "verdict": e["verdict"], "source": "policy, not SPDX"}
        for e in sorted(catalog["not_spdx"] + catalog["not_spdx_expected"],
                        key=lambda e: license_key(e["id"]))]
    for verdict in LICENSE_VERDICTS:
        lines.append(f"  {verdict}:")
        for row in (r for r in rows if r["verdict"] == verdict):
            note = row["source"]
            if row.get("category"):
                note += f" — {row['category']}"
            if row.get("deprecated"):
                note += " — deprecated SPDX ID"
            lines.append(f"    - {json.dumps(row['id'])}  # {note}")
    return "\n".join(lines) + "\n"


def render_markdown(catalog: dict, versions: dict[str, str], seen: Counter) -> str:
    entries = catalog["entries"]
    counts = Counter((e["verdict"], e["source"]) for e in entries)
    lines = [
        "# License catalog (draft)", "",
        f"SPDX License List {versions['spdx']} ({len(entries)} identifiers), "
        f"ScanCode LicenseDB {versions['scancode']}.", "",
        "| Verdict | From the policy | From ScanCode | Unclassified | Total |",
        "|---|---|---|---|---|",
    ]
    for verdict in LICENSE_VERDICTS:
        row = [counts[(verdict, s)] for s in ("policy", "scancode", "unclassified")]
        lines.append(f"| {verdict} | " + " | ".join(map(str, row)) + f" | {sum(row)} |")
    lines.append("")

    if catalog["disagreements"]:
        lines += ["## Policy choices ScanCode disagrees with", "",
                  "The policy wins; check that each one is deliberate.", "",
                  "| License | Policy | ScanCode would say | ScanCode category |",
                  "|---|---|---|---|"]
        lines += [f"| `{d['id']}` | {d['policy']} | {d['scancode']} | {d['category']} |"
                  for d in catalog["disagreements"]]
        lines.append("")

    expected = Counter(e["reason"] for e in catalog["not_spdx_expected"])
    if catalog["not_spdx"] or expected:
        lines += ["## Policy entries that aren't SPDX identifiers", ""]
        if catalog["not_spdx"]:
            lines += ["Only match an SBOM label written exactly that way: check that each "
                      "one isn't a mistake.", "",
                      "| Entry | Verdict | ScanCode key to use instead |", "|---|---|---|"]
            lines += [f"| `{e['id']}` | {e['verdict']} | "
                      + (f"`{e['suggestion']}`" if e["suggestion"] else "_none found_") + " |"
                      for e in catalog["not_spdx"]]
        else:
            lines.append("None that looks like a mistake.")
        if expected:
            lines += ["", f"Not listed, written on purpose (license-catalog.json, "
                          f"`not_spdx_expected`): {expected['scancode-key']} LicenseRef keys "
                          f"of live ScanCode licenses, {expected['listed-name']} listed names "
                          f"of licenses with no SPDX identifier."]
        lines.append("")

    if catalog["deprecated_in_policy"]:
        lines += ["## Deprecated SPDX identifiers in the policy", ""]
        lines += [f"- `{i}`" for i in catalog["deprecated_in_policy"]]
        lines.append("")

    unclassified = [e for e in entries if e["source"] == "unclassified"]
    if unclassified:
        lines += ["## SPDX identifiers with no ScanCode category", "",
                  "Classified with the policy's `unknown` verdict; to decide by hand.", ""]
        lines += [f"- `{e['id']}`" + (" (deprecated SPDX ID)" if e["deprecated"] else "")
                  for e in unclassified]
        lines.append("")

    if seen:
        lines += ["## Labels left unclassified by gate runs", "",
                  "What the SBOMs actually contain: candidates for the alias table "
                  "(license_ids.py) or for the lists.", "",
                  "| Label | Reports |", "|---|---|"]
        lines += [f"| `{label}` | {n} |" for label, n in seen.most_common()]
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", required=True, type=Path)
    ap.add_argument("--gate-report", action="append", default=[], type=Path,
                    help="A licenses.json written by license_gate.py (repeatable)")
    ap.add_argument("--spdx-licenses", default=SPDX_LICENSES_URL)
    ap.add_argument("--spdx-exceptions", default=SPDX_EXCEPTIONS_URL)
    ap.add_argument("--scancode", default=SCANCODE_URL)
    ap.add_argument("--output-dir", default=Path("security-reports/license-catalog"), type=Path)
    args = ap.parse_args()

    try:
        spdx = fetch_json(args.spdx_licenses)
        exceptions = fetch_json(args.spdx_exceptions)
        scancode = fetch_json(args.scancode)
        lic_policy = load_policy(args.policy).get("licenses") or {}
        catalog = build_catalog(spdx["licenses"], exceptions["exceptions"], scancode, lic_policy,
                                listed_names(args.policy))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # A missing/unreadable source or policy (licenses.lists_file
        # included), or a source file of the wrong kind (KeyError).
        print(f"::error:: cannot build the catalog: {exc!r}", file=sys.stderr)
        return 2
    versions = {"spdx": spdx.get("licenseListVersion", "?"),
                "scancode": f"({len(scancode)} licenses)"}

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "license-catalog.yml").write_text(render_yaml(catalog, versions),
                                                         encoding="utf-8")
    md = render_markdown(catalog, versions, seen_labels(args.gate_report))
    (args.output_dir / "license-catalog.md").write_text(md, encoding="utf-8")
    (args.output_dir / "license-catalog.json").write_text(
        json.dumps(catalog, indent=2, ensure_ascii=False), encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
