#!/usr/bin/env python3
# Copyright (C) 2026 Duck Apps Contributor
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Self-test for check-text-protocols.py using synthetic source trees."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

CHECKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-text-protocols.py")
CARD = "feature/demo/presentation/src/main/kotlin/DemoCard.kt"
NATIVE = "capability/demo/data/src/main/cpp/demo/early.cpp"


class TextProtocolCheckerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = self._directory.name
        self.allowed: list[dict] = []

    def tearDown(self) -> None:
        self._directory.cleanup()

    def write(self, relative_path: str, content: str) -> None:
        path = os.path.join(self.root, relative_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    def allow(self, relative_path: str, reason: str = "decodes a wire format") -> None:
        self.allowed.append({"path": relative_path, "reason": reason})

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        policy = {
            "schema_version": 1,
            "kotlin_roots": ["feature/*/presentation/src/main", "app/src/main"],
            "native_roots": ["capability/*/data/src/main/cpp"],
            "allowed": self.allowed,
        }
        self.write(".github/policies/text-protocols.json", json.dumps(policy))
        return subprocess.run([sys.executable, CHECKER, "--repo-root", self.root],
                              capture_output=True, text=True, check=False)

    def assert_accepted(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def assert_rejected(self, *expected: str) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 1, result.stdout)
        for text in expected:
            self.assertIn(text, result.stderr)

    def test_accepts_typed_decisions(self) -> None:
        self.write(CARD, "fun icon(row: Row) = when (row.kind) {\n    Kind.VDSO -> Icons.Memory\n    else -> null\n}\n")
        self.assert_accepted()

    def test_rejects_a_literal_comparison(self) -> None:
        self.write(CARD, 'fun hidden(result: Result) = result.label == "ksuThroneHunt"\n')
        self.assert_rejected(f"{CARD}:1: compares with a string literal")

    def test_rejects_a_literal_when_branch(self) -> None:
        self.write(CARD, 'fun icon(title: String) = when (title) {\n    "Trust root" -> 1\n    else -> 0\n}\n')
        self.assert_rejected(f"{CARD}:2: branches on a string literal")

    def test_rejects_searching_text_for_a_literal(self) -> None:
        self.write(CARD, 'fun grant(summary: String) = summary.contains(\n    "key visibility",\n    ignoreCase = true,\n)\n')
        self.assert_rejected(f"{CARD}:1: searches text for a literal")

    def test_rejects_stripping_a_literal_prefix(self) -> None:
        self.write(CARD, 'fun name(method: String) = method.removePrefix("MSD checker: ")\n')
        self.assert_rejected("searches text for a literal")

    def test_rejects_membership_in_a_literal_set(self) -> None:
        self.write(CARD, 'fun grant(title: String) = title in setOf("Grant self-domain", "Grant handle")\n')
        self.assert_rejected("looks text up in a literal set")

    def test_rejects_comparing_a_display_field_with_a_variable(self) -> None:
        self.write(CARD, "fun find(facts: List<Fact>, label: String) = facts.first { it.label.equals(label, true) }\n")
        self.assert_rejected("compares a display field")

    def test_accepts_comparing_typed_fields(self) -> None:
        self.write(CARD, "fun rows(rules: List<Rule>, verdict: Verdict) = rules.filter { it.verdict == verdict }\n"
                         "fun hit(result: Result) = result.method == Method.KSU_THRONE_HUNT\n")
        self.assert_accepted()

    def test_ignores_literals_and_comments(self) -> None:
        self.write(CARD, '// label == "x" and summary.contains("y")\n'
                         'val note = "compare with label == \\"x\\" or when (x) { \\"a\\" -> 1 }"\n'
                         '/* title.startsWith("z") */\n')
        self.assert_accepted()

    def test_does_not_scan_tests(self) -> None:
        self.write("feature/demo/presentation/src/test/kotlin/DemoTest.kt", 'val hit = row.label == "State"\n')
        self.assert_accepted()

    def test_rejects_native_finding_label_matching(self) -> None:
        self.write(NATIVE, 'if (finding.label == "Emulator device node") { hit = true; }\n'
                           'if (finding.group == "TRANSLATION") { bridge = true; }\n')
        self.assert_rejected(f"{NATIVE}:1: compares a finding field", f"{NATIVE}:2: compares a finding field")

    def test_rejects_native_finding_field_searches_and_strcmp(self) -> None:
        self.write(NATIVE, 'bool a = finding.label.find("qemu") != npos;\nbool b = strcmp(item->title, "x") == 0;\n')
        self.assert_rejected("searches a finding field", "compares a finding field with strcmp")

    def test_accepts_native_platform_text_and_typed_fields(self) -> None:
        self.write(NATIVE, 'if (read_property("ro.kernel.qemu") == "1") { add(Group::kEnvironment); }\n'
                           'if (finding.group == SnapshotGroup::kTranslation) { bridge = true; }\n'
                           '// finding.label == "old" was a text protocol\n')
        self.assert_accepted()

    def test_accepts_an_allowlisted_codec(self) -> None:
        self.write(CARD, 'fun flag(value: String?) = value == "1"\n')
        self.allow(CARD)
        self.assert_accepted()

    def test_rejects_an_allowance_the_file_no_longer_needs(self) -> None:
        self.write(CARD, "fun flag(value: Flag) = value == Flag.ON\n")
        self.allow(CARD)
        self.assert_rejected("allowlisted but no longer reads text")

    def test_rejects_an_allowlisted_file_that_does_not_exist(self) -> None:
        self.allow("app/src/main/java/Gone.kt")
        self.assert_rejected("allowlisted but does not exist")

    def test_requires_a_reason(self) -> None:
        self.write(CARD, 'fun flag(value: String?) = value == "1"\n')
        self.allow(CARD, reason=" ")
        result = self.run_checker()
        self.assertEqual(result.returncode, 2)
        self.assertIn("must state a reason", result.stderr)

    def test_rejects_duplicate_entries(self) -> None:
        self.allow(CARD)
        self.allow(CARD)
        result = self.run_checker()
        self.assertEqual(result.returncode, 2)
        self.assertIn("allowed twice", result.stderr)


if __name__ == "__main__":
    unittest.main()
