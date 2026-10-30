# SPDX-FileCopyrightText: 2026 THALES
#
# SPDX-License-Identifier: MIT

"""Unit tests of security/scripts/license_gate.py (expression evaluation, policy errors)."""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import license_gate as gate  # noqa: E402

TABLE = {gate.license_key(label): verdict for label, verdict in (
    ("MIT", "allow"),
    ("Apache-2.0", "allow"),
    ("GPL-2.0-only", "review"),
    ("MPL-2.0", "review"),
    ("CC-BY-NC-4.0", "deny"),
    ("MATPLOTLIB License 1.3.0 or Later", "allow"),
    ("Apache-2.0 with Commons-Clause-1.0", "review"),
)}


def evaluate(expr: str) -> tuple[str, set]:
    seen: set = set()
    return gate.evaluate(expr, TABLE, "review", seen), seen


class EvaluateTest(unittest.TestCase):
    def test_spdx_operators_still_combine(self):
        self.assertEqual(evaluate("MIT OR CC-BY-NC-4.0"), ("allow", set()))
        self.assertEqual(evaluate("MIT AND CC-BY-NC-4.0"), ("deny", set()))
        self.assertEqual(evaluate("(MIT OR GPL-2.0-only) AND MPL-2.0"), ("review", set()))

    def test_listed_name_holding_an_operator_word_matches_whole(self):
        self.assertEqual(evaluate("MATPLOTLIB License 1.3.0 or Later"), ("allow", set()))
        self.assertEqual(evaluate("matplotlib license 1.3.0 OR later"), ("allow", set()))

    def test_unlisted_name_is_reported_whole_not_split_on_words(self):
        # Lowercase `or` / `and` are words: no split, no "Later" fragment.
        self.assertEqual(evaluate("Foo License or Later"),
                         ("review", {"Foo License or Later"}))
        self.assertEqual(evaluate("Bar and Baz License"),
                         ("review", {"Bar and Baz License"}))

    def test_with_an_spdx_exception_falls_back_to_the_base_license(self):
        self.assertEqual(evaluate("MIT WITH LLVM-exception"), ("allow", set()))

    def test_with_a_restricting_clause_does_not_fall_back(self):
        # Commons-Clause isn't an SPDX exception: dropping it would allow a
        # source-available license through Apache-2.0's verdict.
        self.assertEqual(evaluate("Apache-2.0 WITH Commons-Clause"),
                         ("review", {"Apache-2.0 WITH Commons-Clause"}))

    def test_listed_with_label_matches_whatever_its_case(self):
        self.assertEqual(evaluate("Apache-2.0 with Commons-Clause-1.0"), ("review", set()))


class NonPackageTest(unittest.TestCase):
    """SBOM entries that aren't packages get no verdict, only a count."""

    def run_gate(self, components: list) -> dict:
        with tempfile.TemporaryDirectory() as d:
            policy = Path(d) / "policy-global.yml"
            policy.write_text("licenses:\n  unknown: review\n  allow: [MIT]\n", encoding="utf-8")
            sbom = Path(d) / "sbom.json"
            sbom.write_text(json.dumps({"components": components}), encoding="utf-8")
            argv = ["license_gate.py", "--sbom", str(sbom), "--policy", str(policy),
                    "--output-dir", str(Path(d) / "out")]
            with mock.patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()):
                gate.main()
            out = Path(d) / "out"
            report = json.loads((out / "licenses.json").read_text(encoding="utf-8"))
            report["md"] = (out / "licenses.md").read_text(encoding="utf-8")
            return report

    def test_manifests_and_os_are_skipped_and_counted(self):
        report = self.run_gate([
            {"type": "file", "name": "."},
            {"type": "file", "name": "/src/java/pom.xml"},
            {"type": "operating-system", "name": "debian", "version": "12"},
            {"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1",
             "licenses": [{"license": {"id": "MIT"}}]},
            # A package without a license is still checked: unknown verdict.
            {"type": "library", "name": "b", "version": "2", "purl": "pkg:npm/b@2"}])
        self.assertEqual([c["name"] for c in report["components"]], ["a", "b"])
        self.assertEqual((report["summary"]["allow"], report["summary"]["review"]), (1, 1))
        self.assertEqual(report["skipped"], {"file": 2, "operating-system": 1})
        self.assertIn("Not checked: 3 SBOM entries that aren't packages "
                      "(2 file, 1 operating-system).", report["md"])


class PolicyErrorTest(unittest.TestCase):
    def test_missing_lists_file_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as d:
            policy = Path(d) / "policy-global.yml"
            policy.write_text("licenses:\n  lists_file: missing.yml\n", encoding="utf-8")
            sbom = Path(d) / "sbom.json"
            sbom.write_text('{"components": []}', encoding="utf-8")
            argv = ["license_gate.py", "--sbom", str(sbom), "--policy", str(policy),
                    "--output-dir", str(Path(d) / "out")]
            err = io.StringIO()
            with mock.patch.object(sys, "argv", argv), redirect_stderr(err):
                self.assertEqual(gate.main(), 2)
            self.assertIn("::error::", err.getvalue())
            self.assertIn("not found", err.getvalue())


if __name__ == "__main__":
    unittest.main()
