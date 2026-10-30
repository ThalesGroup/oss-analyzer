#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""
Effective policy: the one place that turns policy files into the policy
license_gate.py and aggregate_report.py apply.

1. Merge (merge_policies): an organization base policy (embedded in the
   oss-analyzer image) with a project's own policy-global.yml, which then only
   needs its differences:
     - settings (fail_on, ignore_unfixed, unknown, ...): the project wins;
     - `exceptions` lists: base and project entries add up;
     - license lists (allow / review / deny): a license the project lists
       is moved out of the base's other lists — a project reclassifies a
       license, it never has it in two lists at once;
     - `meta.inherit: false` in the project: no base at all, the project
       policy applies alone.
   Model rules (`by_distribution_model`, see 2.) are not part of this merge:
   they are applied after it, so a model rule of the base beats a project
   reclassifying the same license in its common lists; the project overrides
   it with its own `by_distribution_model.<model>`.
2. Resolution (resolve_policy):
     - distribution model: `licenses.by_distribution_model.<model>`
       reclassifies licenses on top of the common lists, for the model given
       explicitly (OSA_DISTRIBUTION_MODEL), else `meta.distribution_model`;
     - mode: each category's `mode` (enforce | audit) is set, from the
       category's own `mode` in the policy, else the global mode (OSA_MODE),
       else enforce.
   Resolving an already resolved policy changes nothing, so both scripts
   can resolve whatever policy file they're given.
Before either, loading a policy (load_policy) pulls in its license lists:
its `licenses.lists_file`, else a policy-licenses.yml next to it.

The CI/CD component's osa_prepare job resolves the policy through
prepare_settings.py, along with the other settings files. Standalone
command line, for the policy alone:
    python policy.py --project security/policy-global.yml \
                     --base /opt/oss-analyzer/defaults/policy-global.yml \
                     [--distribution-model saas] [--mode audit] \
                     --output security-reports/.osa/policy-global.yml
"""
from __future__ import annotations

import argparse
import copy
import os
import sys
from pathlib import Path
from typing import Any

from license_ids import license_key

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML required:  pip install pyyaml")

DISTRIBUTION_MODELS = ("saas", "distributed", "oss_library")
MODES = ("enforce", "audit")
LICENSE_VERDICTS = ("allow", "review", "deny")
# Policy sections that carry a blocking decision, hence a mode.
MODE_CATEGORIES = ("vulnerabilities", "sast", "secrets", "licenses")
# The settings folder's policy files (see prepare_settings.py for the rest).
POLICY_FILE = "policy-global.yml"
LISTS_FILE = "policy-licenses.yml"

# Version of the settings format (`meta.version`). Bumped only by a change
# a project's settings must be migrated for; a policy declaring another
# version is refused rather than half-understood.
SETTINGS_VERSION = 1
# Every key the scripts read, per section: anything else is reported (a
# typo would otherwise be ignored silently).
SCHEMA = {
    "meta": {"version", "owner", "distribution_model", "inherit"},
    "vulnerabilities": {"fail_on", "ignore_unfixed", "exceptions", "mode"},
    "secrets": {"fail_on_any", "inherit_rules", "mode"},
    "sast": {"fail_on", "inherit_rules", "disabled_rules", "registry_packs", "mode"},
    "licenses": {"unknown", "fail_on_deny", "fail_on_review", "lists_file", "allow", "review",
                 "deny", "by_distribution_model", "exceptions", "mode"},
}
FAIL_ON = ("critical", "high", "medium", "low", "none")
BOOLEANS = {("meta", "inherit"), ("vulnerabilities", "ignore_unfixed"),
            ("secrets", "fail_on_any"), ("secrets", "inherit_rules"),
            ("sast", "inherit_rules"), ("licenses", "fail_on_deny"),
            ("licenses", "fail_on_review")}


def load_policy(path: Path) -> dict:
    """Reads a policy file, its license lists included: those of its
    `licenses.lists_file` (a path relative to the policy's directory) or,
    without that key, of a policy-licenses.yml next to it, if any. The lists
    written in the policy itself reclassify them. The key is gone once
    loaded, so a written-out policy is whole."""
    policy = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    licenses = policy.get("licenses")
    lists_path = lists_file_path(path, policy)
    if isinstance(licenses, dict):
        licenses.pop("lists_file", None)
    if lists_path is None:
        return policy
    if not isinstance(licenses, dict):
        licenses = policy["licenses"] = {}
    lists = yaml.safe_load(lists_path.read_text(encoding="utf-8")) or {}
    licenses.update(reclassify(lists, licenses))
    return policy


def lists_file_path(path: Path, policy: dict) -> Path | None:
    """The license lists file load_policy pulls into the policy read from
    `path` (`policy`, as read, before load_policy drops the key): its
    `licenses.lists_file`, else a policy-licenses.yml next to it, else None.
    A `lists_file` that doesn't exist is an error."""
    licenses = policy.get("licenses")
    explicit = licenses.get("lists_file") if isinstance(licenses, dict) else None
    if explicit:
        lists_path = path.parent / explicit
        if not lists_path.is_file():
            raise ValueError(f"licenses.lists_file of {path}: {lists_path} not found")
        return lists_path
    lists_path = path.parent / LISTS_FILE
    return lists_path if lists_path.is_file() else None


def load_settings_policy(settings_dir: Path) -> dict:
    """A settings folder's policy: its policy-global.yml (lists included, see
    load_policy), or its policy-licenses.yml alone, or {} — each file of the
    folder is optional."""
    if (settings_dir / POLICY_FILE).is_file():
        return load_policy(settings_dir / POLICY_FILE)
    lists_path = settings_dir / LISTS_FILE
    if lists_path.is_file():
        lists = yaml.safe_load(lists_path.read_text(encoding="utf-8")) or {}
        return {"licenses": reclassify(lists, {})}
    return {}


def reclassify(lists: dict, overrides: dict) -> dict:
    """Applies `overrides` (allow/review/deny lists) on top of `lists`: each
    license named in `overrides` leaves whichever list it was in and joins
    its new one. Licenses are compared normalized (license_ids.py), so
    `apache 2.0` and `Apache-2.0` are the same license."""
    moved = {license_key(lic) for verdict in LICENSE_VERDICTS
             for lic in overrides.get(verdict) or []}
    out = {verdict: [lic for lic in lists.get(verdict) or [] if license_key(lic) not in moved]
           for verdict in LICENSE_VERDICTS}
    for verdict in LICENSE_VERDICTS:
        out[verdict] += list(overrides.get(verdict) or [])
    return out


def _holds_license_lists(path: tuple) -> bool:
    """`licenses` itself, or one `licenses.by_distribution_model.<model>`."""
    return path == ("licenses",) or (
        len(path) == 3 and path[:2] == ("licenses", "by_distribution_model"))


def _merge(base: Any, project: Any, path: tuple = ()) -> Any:
    if isinstance(base, dict) and isinstance(project, dict):
        out = dict(base)
        for k, v in project.items():
            out[k] = _merge(base[k], v, path + (k,)) if k in base else copy.deepcopy(v)
        if _holds_license_lists(path):
            out.update(reclassify(base, project))
        return out
    if project is None and isinstance(base, (dict, list)):
        # An empty section (`licenses:` with nothing under it) overrides nothing.
        return copy.deepcopy(base)
    if path and path[-1] == "exceptions" and isinstance(base, list) and isinstance(project, list):
        return copy.deepcopy(base) + copy.deepcopy(project)
    return copy.deepcopy(project)


def merge_policies(base: dict, project: dict) -> dict:
    if (project.get("meta") or {}).get("inherit", True) is False:
        return copy.deepcopy(project)
    return _merge(base, project)


def check_policy(policy: dict) -> list[str]:
    """Raises ValueError on a value the scripts would misread (wrong settings
    version, unknown severity or verdict, non-boolean flag, malformed
    section); returns warnings for the keys no script reads."""
    warnings = []
    for section, value in policy.items():
        if section not in SCHEMA:
            warnings.append(f"unknown section {section!r} — ignored")
            continue
        if value is None:
            continue
        if not isinstance(value, dict):
            raise ValueError(f"{section}: expected a mapping, got {value!r}")
        for key in value:
            if key not in SCHEMA[section]:
                warnings.append(f"{section}.{key}: unknown key — ignored")
        for key in ("exceptions",):
            if value.get(key) is not None and not isinstance(value[key], list):
                raise ValueError(f"{section}.{key}: expected a list, got {value[key]!r}")
    sections = {s: (policy.get(s) or {}) for s in SCHEMA}  # mappings, checked above
    version = sections["meta"].get("version", SETTINGS_VERSION)
    if version != SETTINGS_VERSION:
        raise ValueError(f"meta.version: settings format {version!r} isn't supported by this "
                         f"oss-analyzer version (format {SETTINGS_VERSION})")
    for section in ("vulnerabilities", "sast"):
        fail_on = sections[section].get("fail_on", "high")
        if fail_on not in FAIL_ON:
            raise ValueError(f"{section}.fail_on: {fail_on!r} (expected one of {', '.join(FAIL_ON)})")
    unknown = sections["licenses"].get("unknown", "review")
    if unknown not in LICENSE_VERDICTS:
        raise ValueError(f"licenses.unknown: {unknown!r} (expected one of "
                         f"{', '.join(LICENSE_VERDICTS)})")
    for section, key in sorted(BOOLEANS):
        value = sections[section].get(key)
        if value is not None and not isinstance(value, bool):
            raise ValueError(f"{section}.{key}: expected true or false, got {value!r}")
    return warnings


def resolve_policy(policy: dict, distribution_model: str | None = None,
                   mode: str | None = None) -> dict:
    check_policy(policy)
    out = copy.deepcopy(policy)
    meta = out["meta"] = out.get("meta") or {}
    model = distribution_model or meta.get("distribution_model")
    if model and model not in DISTRIBUTION_MODELS:
        raise ValueError(f"unknown distribution model {model!r} "
                         f"(expected one of {', '.join(DISTRIBUTION_MODELS)})")
    if model:
        meta["distribution_model"] = model

    licenses = out["licenses"] = out.get("licenses") or {}
    by_model = licenses.pop("by_distribution_model", None) or {}
    if model and by_model.get(model):
        licenses.update(reclassify(licenses, by_model[model]))

    global_mode = mode or "enforce"
    if global_mode not in MODES:
        raise ValueError(f"unknown mode {global_mode!r} (expected one of {', '.join(MODES)})")
    for category in MODE_CATEGORIES:
        section = out[category] = out.get(category) or {}
        section_mode = section.get("mode") or global_mode
        if section_mode not in MODES:
            raise ValueError(f"{category}.mode: unknown mode {section_mode!r}")
        section["mode"] = section_mode
    return out


def effective_policy(path: Path, base: Path | None = None) -> dict:
    """The policy a script applies: `path` (merged onto `base` when given),
    resolved with OSA_DISTRIBUTION_MODEL / OSA_MODE from the environment —
    set by the CI/CD component, unset locally."""
    policy = load_policy(path)
    if base is not None and base.is_file():
        policy = merge_policies(load_policy(base), policy)
    return resolve_policy(policy,
                          distribution_model=os.environ.get("OSA_DISTRIBUTION_MODEL") or None,
                          mode=os.environ.get("OSA_MODE") or None)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", type=Path, help="Project policy (optional: base alone if absent)")
    ap.add_argument("--base", type=Path, help="Organization base policy")
    ap.add_argument("--distribution-model", choices=DISTRIBUTION_MODELS)
    ap.add_argument("--mode", choices=MODES)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()

    try:
        base = load_policy(args.base) if args.base and args.base.is_file() else {}
        project = load_policy(args.project) if args.project and args.project.is_file() else {}
        if not base and not project:
            print("::error:: no policy file found (neither --base nor --project).", file=sys.stderr)
            return 2
        for warning in check_policy(project or base):
            print(f"::warning:: {warning}")
        merged = merge_policies(base, project) if project else base
        policy = resolve_policy(merged, args.distribution_model, args.mode)
    except ValueError as exc:
        print(f"::error:: {exc}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(yaml.safe_dump(policy, sort_keys=False, allow_unicode=True),
                           encoding="utf-8")
    meta = policy.get("meta") or {}
    print(f"Effective policy written to {args.output}")
    print(f"  base: {args.base if base else 'none'} | project: "
          f"{args.project if project else 'none'}"
          + (" (meta.inherit: false)" if project and meta.get("inherit") is False else ""))
    print(f"  distribution model: {meta.get('distribution_model', 'undefined')}")
    print("  modes: " + ", ".join(f"{c}={policy[c]['mode']}" for c in MODE_CATEGORIES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
