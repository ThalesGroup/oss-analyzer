#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""
Resolves every settings file of oss-analyzer, for the CI/CD component's
osa_prepare job: the organization defaults embedded in the image, completed
by the project's settings folder (OSA_SETTINGS_DIR, `security/` by
default). One naming rule, `policy-<facet>.<the tool's own format>`, and
one behavior: each project file is optional, and completes the default
rather than replacing it.

  policy-global.yml     thresholds, modes, exceptions, settings: merged on
                        top of the base (policy.py; `meta.inherit: false`
                        applies it alone)
  policy-licenses.yml   allow / review / deny lists: reclassify licenses on
                        top of the base's lists (policy.py)
  policy-semgrep.yml    Semgrep rules: run in addition to oss-analyzer's.
                        `sast.disabled_rules` drops some of ours;
                        `sast.inherit_rules: false` runs the project's alone.
                        The registry rule packs are `sast.registry_packs`
                        in policy-global.yml (a project's list replaces it)
  policy-gitleaks.toml  Gitleaks rules and allowlist: extend oss-analyzer's
                        (which extends Gitleaks' defaults) through an
                        `[extend] path` added here — so the project file
                        must not have its own [extend];
                        `secrets.inherit_rules: false` uses it alone

A project file that is a byte-for-byte copy of the default is treated as
absent (and logged so): oss-analyzer's own repository, whose security/ is
the defaults, or a project that copied them.

Written to --output-dir, which every later job reads:
  policy-global.yml                  the effective policy, lists included
  semgrep/policy-semgrep.yml         oss-analyzer's rules (minus disabled ones)
  semgrep/policy-semgrep.project.yml the project's rules
  semgrep-packs.txt                  the registry rule packs, one per line
  policy-gitleaks.toml               the Gitleaks config to pass to --config
  policy-gitleaks.base.toml          oss-analyzer's, when the project extends it
Both Semgrep files stay in one folder: Semgrep prefixes reported rule IDs
with the folder of their file, which keeps the IDs the same as before.
The Gitleaks `[extend] path` is relative to the working directory (how
Gitleaks resolves it): run this, and Gitleaks, from the project's root.

Usage:
    python prepare_settings.py --defaults /opt/oss-analyzer/defaults \
        --settings-dir security --output-dir security-reports/.osa \
        [--distribution-model saas] [--mode audit]
"""
from __future__ import annotations

import argparse
import shutil
import sys
import tomllib
from pathlib import Path

import yaml

from policy import (LISTS_FILE, POLICY_FILE, check_policy, load_policy,
                    merge_policies, reclassify, resolve_policy)

SEMGREP_FILE = "policy-semgrep.yml"
GITLEAKS_FILE = "policy-gitleaks.toml"
SEMGREP_PROJECT_FILE = "policy-semgrep.project.yml"
SEMGREP_PACKS_FILE = "semgrep-packs.txt"
GITLEAKS_BASE_FILE = "policy-gitleaks.base.toml"

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")


def _flag(section: dict, key: str, name: str) -> bool:
    value = section.get(key, True)
    if not isinstance(value, bool):
        raise ValueError(f"{name}.{key}: expected true or false, got {value!r}")
    return value


def _rules(n: int) -> str:
    return f"{n} rule" + ("" if n == 1 else "s")


SETTINGS_FILES = (POLICY_FILE, LISTS_FILE, SEMGREP_FILE, GITLEAKS_FILE)


def identical_to_default(settings: Path, defaults: Path) -> list[str]:
    """The project's settings files that are byte-for-byte copies of the
    defaults: treated as absent (oss-analyzer's own repository, whose
    security/ *is* the defaults, or a project that copied them) — completing
    the defaults with themselves would run every Semgrep rule twice and make
    Gitleaks extend itself."""
    return [name for name in SETTINGS_FILES
            if (settings / name).is_file() and (defaults / name).is_file()
            and (settings / name).read_bytes() == (defaults / name).read_bytes()]


def _project_file(settings: Path, defaults: Path, name: str) -> Path | None:
    path = settings / name
    if not path.is_file() or name in identical_to_default(settings, defaults):
        return None
    return path


def _semgrep_rules(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, list):
        raise ValueError(f"{path}: not a Semgrep rules file (no `rules:` list)")
    return rules


# --------------------------------------------------------------------------- #
#  Facets
# --------------------------------------------------------------------------- #
def prepare_policy(defaults: Path, settings: Path, model: str | None,
                   mode: str | None) -> tuple[dict, str, list[str]]:
    """→ (effective policy, where it comes from, warnings on the project's
    policy: keys no script reads)."""
    base = load_policy(defaults / POLICY_FILE)
    policy_file = _project_file(settings, defaults, POLICY_FILE)
    lists_file = _project_file(settings, defaults, LISTS_FILE)
    if policy_file:
        project = load_policy(policy_file)  # its policy-licenses.yml included
    elif lists_file:
        lists = yaml.safe_load(lists_file.read_text(encoding="utf-8")) or {}
        project = {"licenses": reclassify(lists, {})}
    else:
        project = {}
    if not project:
        return resolve_policy(base, model, mode), "oss-analyzer default", []
    warnings = [f"{POLICY_FILE}: {w}" for w in check_policy(project)]
    origin = ("project alone (meta.inherit: false)"
              if (project.get("meta") or {}).get("inherit", True) is False
              else "oss-analyzer default + project")
    return resolve_policy(merge_policies(base, project), model, mode), origin, warnings


def prepare_semgrep(defaults: Path, settings: Path, out: Path,
                    sast: dict) -> tuple[str, list[str]]:
    """Writes out/semgrep/*.yml → (summary, warnings)."""
    inherit = _flag(sast, "inherit_rules", "sast")
    disabled = sast.get("disabled_rules") or []
    if not isinstance(disabled, list) or not all(isinstance(r, str) for r in disabled):
        raise ValueError(f"sast.disabled_rules: expected a list of rule IDs, got {disabled!r}")
    warnings, parts = [], []
    folder = out / "semgrep"
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)

    ours_ids: set[str] = set()
    if inherit:
        rules = _semgrep_rules(defaults / SEMGREP_FILE)
        ours_ids = {r.get("id") for r in rules}
        for rule_id in sorted(set(disabled) - ours_ids):
            warnings.append(f"sast.disabled_rules: {rule_id!r} isn't one of oss-analyzer's "
                            f"rules — ignored")
        if disabled:
            kept = [r for r in rules if r.get("id") not in disabled]
            (folder / SEMGREP_FILE).write_text(
                yaml.safe_dump({"rules": kept}, sort_keys=False, allow_unicode=True, width=1000),
                encoding="utf-8")
        else:
            shutil.copyfile(defaults / SEMGREP_FILE, folder / SEMGREP_FILE)
            kept = rules
        parts.append(f"oss-analyzer ({_rules(len(kept))}"
                     + (f", {len(rules) - len(kept)} disabled" if len(kept) != len(rules) else "")
                     + ")")
    elif disabled:
        warnings.append("sast.disabled_rules is ignored with sast.inherit_rules: false")

    packs = sast.get("registry_packs") or []
    if not isinstance(packs, list) or not all(isinstance(p, str) and p.strip() for p in packs):
        raise ValueError(f"sast.registry_packs: expected a list of Semgrep configs "
                         f"(e.g. p/default), got {packs!r}")
    (out / SEMGREP_PACKS_FILE).write_text("".join(f"{p.strip()}\n" for p in packs),
                                          encoding="utf-8")
    if packs:
        parts.append(f"registry packs ({' '.join(packs)})")

    project = _project_file(settings, defaults, SEMGREP_FILE)
    if project:
        project_rules = _semgrep_rules(project)
        shutil.copyfile(project, folder / SEMGREP_PROJECT_FILE)
        parts.append(f"project ({_rules(len(project_rules))})")
        for rule_id in sorted({r.get("id") for r in project_rules} & (ours_ids - set(disabled))):
            warnings.append(f"Semgrep rule {rule_id!r} is defined by both oss-analyzer and the "
                            f"project: both run. To replace oss-analyzer's, add it to "
                            f"sast.disabled_rules.")
    return " + ".join(parts) or "none (no rule at all: Semgrep is skipped)", warnings


def prepare_gitleaks(defaults: Path, settings: Path, out: Path, secrets: dict) -> str:
    """Writes out/policy-gitleaks.toml (and its base) → summary."""
    inherit = _flag(secrets, "inherit_rules", "secrets")
    ours = defaults / GITLEAKS_FILE
    project = _project_file(settings, defaults, GITLEAKS_FILE)
    target = out / GITLEAKS_FILE
    (out / GITLEAKS_BASE_FILE).unlink(missing_ok=True)
    if not project:
        shutil.copyfile(ours, target)
        return "oss-analyzer default"
    text = project.read_text(encoding="utf-8")
    parsed = tomllib.loads(text)  # invalid TOML → TOMLDecodeError (a ValueError)
    if not inherit:
        shutil.copyfile(project, target)
        return "project alone (secrets.inherit_rules: false)"
    if "extend" in parsed:
        # Gitleaks follows two extends at most: project → oss-analyzer →
        # Gitleaks' defaults. A third level silently drops the defaults.
        raise ValueError(
            f"{project} has its own [extend]: remove it — oss-analyzer extends this file "
            f"from its own config, which extends Gitleaks' defaults — or set "
            f"secrets.inherit_rules: false to use the file alone.")
    shutil.copyfile(ours, out / GITLEAKS_BASE_FILE)
    base_path = (out / GITLEAKS_BASE_FILE).as_posix()
    # Appended, not prepended: a table placed before the file's root keys
    # (e.g. `title`) would capture them.
    composed = (text.rstrip("\n") + "\n\n# Added by oss-analyzer (prepare_settings.py): "
                "extends oss-analyzer's rules and allowlist.\n"
                f"[extend]\npath = {base_path!r}\n")
    tomllib.loads(composed)
    target.write_text(composed, encoding="utf-8")
    return "project, extending oss-analyzer's (itself extending Gitleaks' defaults)"


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--defaults", required=True, type=Path,
                    help="oss-analyzer's settings folder (the image's defaults)")
    ap.add_argument("--settings-dir", required=True, type=Path,
                    help="The project's settings folder (may be absent)")
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--distribution-model")
    ap.add_argument("--mode")
    args = ap.parse_args()

    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    settings = args.settings_dir
    try:
        policy, policy_origin, policy_warnings = prepare_policy(
            args.defaults, settings, args.distribution_model, args.mode)
        (out / POLICY_FILE).write_text(
            yaml.safe_dump(policy, sort_keys=False, allow_unicode=True), encoding="utf-8")
        semgrep, semgrep_warnings = prepare_semgrep(args.defaults, settings, out,
                                                    policy.get("sast") or {})
        warnings = policy_warnings + semgrep_warnings
        gitleaks = prepare_gitleaks(args.defaults, settings, out, policy.get("secrets") or {})
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"::error:: {exc}", file=sys.stderr)
        return 2

    found = sorted(p.name for p in settings.glob("policy-*")) if settings.is_dir() else []
    identical = identical_to_default(settings, args.defaults)
    found = [f"{n} (identical to the default: ignored)" if n in identical else n for n in found]
    meta = policy.get("meta") or {}
    print(f"Settings resolved into {out} — project folder {settings}: "
          + (", ".join(found) if found else "none (oss-analyzer defaults only)"))
    print(f"  policy:   {policy_origin} | distribution model: "
          f"{meta.get('distribution_model', 'undefined')} | modes: "
          + ", ".join(f"{c}={(policy.get(c) or {}).get('mode')}"
                      for c in ("vulnerabilities", "sast", "secrets", "licenses")))
    print(f"  semgrep:  {semgrep}")
    print(f"  gitleaks: {gitleaks}")
    for warning in warnings:
        print(f"::warning:: {warning}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
