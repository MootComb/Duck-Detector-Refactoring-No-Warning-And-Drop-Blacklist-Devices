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

"""Self-test for check-reflection-boundaries.py using synthetic source trees."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

CHECKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-reflection-boundaries.py")
SOURCE = "feature/demo/data/src/main/kotlin/Demo.kt"


class ReflectionBoundaryCheckerTest(unittest.TestCase):
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

    def allow(self, relative_path: str, *uses: str, reason: str = "hidden platform API probe") -> None:
        self.allowed.append({"path": relative_path, "uses": list(uses), "reason": reason})

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        policy = {"schema_version": 1, "scan_roots": ["feature"], "allowed": self.allowed}
        self.write(".github/policies/reflection-allowlist.json", json.dumps(policy))
        return subprocess.run([sys.executable, CHECKER, "--repo-root", self.root],
                              capture_output=True, text=True, check=False)

    def assert_accepted(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def assert_rejected(self, *expected: str) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for message in expected:
            self.assertIn(message, result.stderr)

    def assert_policy_error(self, expected: str) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(expected, result.stderr)

    def test_accepts_code_without_reflection(self) -> None:
        self.write(SOURCE, "fun ok(): String = \"plain\"\n")
        self.assert_accepted()

    def test_rejects_member_lookup_outside_the_allowlist(self) -> None:
        self.write(SOURCE, 'fun probe() = Class.forName("android.os.SystemProperties").getMethod("get")\n')
        self.assert_rejected(f"{SOURCE}:1: Class.forName is operations reflection", "member lookup is operations")

    def test_accepts_allowlisted_operations(self) -> None:
        self.write(SOURCE, 'fun probe() = Class.forName("android.os.ServiceManager")\n')
        self.allow(SOURCE, "operations")
        self.assert_accepted()

    def test_operations_allowance_does_not_permit_class_identity(self) -> None:
        self.write(SOURCE, 'fun probe(t: Throwable) = Class.forName("x").name + t.javaClass.simpleName\n')
        self.allow(SOURCE, "operations")
        self.assert_rejected("runtime class name is class_identity reflection outside the allowlist")

    def test_finds_class_identity_inside_a_string_template(self) -> None:
        self.write(SOURCE, 'fun describe(t: Throwable) = "failed: ${t.javaClass.simpleName}"\n')
        self.assert_rejected(f"{SOURCE}:1: runtime class name is class_identity")

    def test_finds_class_identity_in_a_raw_string_template(self) -> None:
        self.write(SOURCE, 'fun describe(t: Throwable) = """failed: ${t::class.java.name}"""\n')
        self.assert_rejected("runtime class name is class_identity")

    def test_ignores_reflection_words_in_literals_and_comments(self) -> None:
        self.write(SOURCE, "\n".join([
            '// Class.forName("x").getMethod("get")',
            '/* outer /* t.javaClass.simpleName */ still comment: Class.forName("x") */',
            'val hint = "call getDeclaredField(name) or javaClass.name"',
            "val quote = '\"'",
            "",
        ]))
        self.assert_accepted()

    def test_type_tokens_and_caught_wrappers_are_not_reflection(self) -> None:
        self.write(SOURCE, "\n".join([
            "import java.lang.reflect.InvocationTargetException",
            "fun manager(context: Context) = context.getSystemService(NotificationManager::class.java)",
            "fun unwrap(t: Throwable) = if (t is InvocationTargetException) t.cause else t",
            "",
        ]))
        self.assert_accepted()

    def test_other_java_lang_reflect_types_are_operations(self) -> None:
        self.write(SOURCE, "import java.lang.reflect.Proxy\n")
        self.assert_rejected("java.lang.reflect is operations reflection")

    def test_java_class_names_are_class_identity(self) -> None:
        self.write("feature/demo/data/src/main/java/Demo.java",
                   "class Demo { String name(Object o) { return o.getClass().getSimpleName(); } }\n")
        self.assert_rejected("Demo.java:1: runtime class name is class_identity")

    def test_rejects_an_allowance_the_file_no_longer_needs(self) -> None:
        self.write(SOURCE, 'fun probe() = Class.forName("x")\n')
        self.allow(SOURCE, "operations", "class_identity")
        self.assert_rejected(f"{SOURCE}: allowlisted for class_identity but no longer uses it")

    def test_rejects_an_allowlisted_file_that_does_not_exist(self) -> None:
        self.write(SOURCE, "fun ok() = 1\n")
        self.allow("feature/demo/data/src/main/kotlin/Gone.kt", "operations")
        self.assert_rejected("Gone.kt: allowlisted but does not exist")

    def test_requires_a_reason(self) -> None:
        self.write(SOURCE, 'fun probe() = Class.forName("x")\n')
        self.allow(SOURCE, "operations", reason="  ")
        self.assert_policy_error("must state a reason")

    def test_rejects_unknown_kinds(self) -> None:
        self.write(SOURCE, "fun ok() = 1\n")
        self.allow(SOURCE, "annotations")
        self.assert_policy_error("uses must name distinct kinds")

    def test_rejects_duplicate_entries(self) -> None:
        self.write(SOURCE, 'fun probe() = Class.forName("x")\n')
        self.allow(SOURCE, "operations")
        self.allow(SOURCE, "operations")
        self.assert_policy_error("is allowed twice")


if __name__ == "__main__":
    unittest.main(verbosity=2)
