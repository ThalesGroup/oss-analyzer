#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""
Checks license_gate.py's output on the synthetic SBOM (sbom-fixture.cdx.json)
against sbom-fixture.expected.json, in both modes:
  - enforce: every component's verdict as expected, and the gate fails
    (the fixture holds a denied license);
  - audit: same verdicts, the gate doesn't fail but reports would_fail.
Standard library only.

Usage:
    python check_license_fixture.py <enforce licenses.json> <audit licenses.json> <expected.json>
"""
import json
import sys


def main() -> int:
    enforce, audit, expected = (json.load(open(p, encoding="utf-8")) for p in sys.argv[1:4])
    errors = []

    for mode, result in (("enforce", enforce), ("audit", audit)):
        actual = {c["name"]: c["verdict"] for c in result.get("components", [])}
        for name, verdict in expected["verdicts"].items():
            if actual.get(name) != verdict:
                errors.append(f"{mode}: {name} is {actual.get(name)}, expected {verdict}")
        for name in sorted(set(actual) - set(expected["verdicts"])):
            errors.append(f"{mode}: unexpected component {name} ({actual[name]})")

    if not enforce.get("failed"):
        errors.append("enforce: the gate should fail (denied license)")
    if audit.get("failed") or not audit.get("would_fail"):
        errors.append(f"audit: expected failed=False and would_fail=True, got "
                      f"failed={audit.get('failed')} would_fail={audit.get('would_fail')}")

    print(f"enforce summary: {enforce.get('summary')} failed={enforce.get('failed')}")
    print(f"audit summary:   {audit.get('summary')} failed={audit.get('failed')} "
          f"would_fail={audit.get('would_fail')}")
    if errors:
        print("\nUnmet expectations:\n  - " + "\n  - ".join(errors), file=sys.stderr)
        return 1
    print(f"Every expectation met ({len(expected['verdicts'])} components, both modes).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
