#!/usr/bin/env python3
# Copyright (C) 2026 Duck Apps Contributor
# If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

"""Exercise bot publication against real temporary Git repositories and a fake GitHub API."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("publish-android-toolchain-update.py")
SPEC = importlib.util.spec_from_file_location("android_toolchain_publisher", SCRIPT)
PUBLISHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISHER)

PROPERTIES = "duckdetector.android.ndk=30.0.100\nduckdetector.android.cmake=4.1.2\nduckdetector.android.buildTools=37.0.0\nother.setting=unchanged\n"
BRANCH = PUBLISHER.UPDATER.target_branch(PROPERTIES.replace("30.0.100", "30.0.200"))
REPORT = {"branch": BRANCH, "changes": [{"property": "duckdetector.android.ndk", "from": "30.0.100", "to": "30.0.200"}]}


class PublicationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.origin = self.root / "origin.git"
        self.git("init", "--bare", "--initial-branch=main", str(self.origin), cwd=self.root)
        seed = self.root / "seed"
        self.git("clone", str(self.origin), str(seed), cwd=self.root)
        self.git("config", "user.name", "Test", cwd=seed)
        self.git("config", "user.email", "test@example.invalid", cwd=seed)
        (seed / "gradle.properties").write_text(PROPERTIES)
        (seed / "unrelated.txt").write_text("original\n")
        self.git("add", ".", cwd=seed)
        self.git("commit", "-m", "initial", cwd=seed)
        self.git("push", "origin", "main", cwd=seed)
        self.seed = seed
        self.pr = None
        self.ci_runs = set()
        self.creates = 0
        self.dispatches = 0
        self.fail_create = False
        self.fail_dispatch = False
        self.count = 0
        self.body = self.root / "pr-body.md"
        self.body.write_text("Dependency update\n")
        self.checkout()

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *args, cwd=None, raw=False):
        output = subprocess.check_output(["git", *args], cwd=cwd or self.repo,
                                         stderr=subprocess.DEVNULL).decode("utf-8")
        return output if raw else output.strip()

    def checkout(self):
        self.count += 1
        self.repo = self.root / f"checkout-{self.count}"
        self.git("clone", "--branch", "main", str(self.origin), str(self.repo), cwd=self.root)
        path = self.repo / "gradle.properties"
        path.write_bytes(path.read_bytes().replace(b"30.0.100", b"30.0.200"))

    def execute(self, *args):
        if args[0] == "git":
            return self.git(*args[1:], raw=True)
        self.assertEqual(args[0], "gh")
        if args[1:3] == ("pr", "list"):
            if self.pr:
                sha = self.git("rev-parse", f"refs/heads/{BRANCH}", cwd=self.origin)
                return json.dumps([{**self.pr, "headRefOid": sha}])
            return "[]"
        if args[1:3] == ("pr", "create"):
            if self.fail_create:
                raise RuntimeError("Simulated PR API failure after successful push")
            self.pr = {"number": 17, "state": "OPEN"}
            self.creates += 1
            return "https://example.invalid/pr/17"
        if args[1:3] == ("run", "list"):
            sha = args[args.index("--commit") + 1]
            self.assertEqual(args[args.index("--event") + 1], "workflow_dispatch")
            return json.dumps([{"databaseId": 1}] if sha in self.ci_runs else [])
        if args[1:3] == ("workflow", "run"):
            if self.fail_dispatch:
                raise RuntimeError("Simulated CI dispatch failure after PR creation")
            sha = self.git("rev-parse", f"refs/heads/{BRANCH}", cwd=self.origin)
            self.ci_runs.add(sha)
            self.dispatches += 1
            return ""
        self.fail(f"Unexpected API call: {args}")

    def publish(self, report=REPORT):
        PUBLISHER.publish(report, self.body, "main", self.execute)

    def test_publication_and_repeat_are_idempotent(self):
        self.publish()
        self.checkout()
        self.publish()
        self.assertEqual((self.creates, self.dispatches), (1, 1))
        self.assertEqual(self.git("diff", "--name-only", "main", BRANCH, cwd=self.origin), "gradle.properties")

    def test_retry_after_ci_dispatch_failure(self):
        self.fail_dispatch = True
        with self.assertRaisesRegex(RuntimeError, "CI dispatch"):
            self.publish()
        self.fail_dispatch = False
        self.checkout()
        self.publish()
        self.assertEqual((self.creates, self.dispatches), (1, 1))

    def test_retry_after_push_before_pr_creation(self):
        self.fail_create = True
        with self.assertRaisesRegex(RuntimeError, "PR API"):
            self.publish()
        old_sha = self.git("rev-parse", BRANCH, cwd=self.origin)
        self.fail_create = False
        self.checkout()
        self.publish()
        self.assertEqual(self.git("rev-parse", BRANCH, cwd=self.origin), old_sha)
        self.assertEqual((self.creates, self.dispatches), (1, 1))

    def test_closed_and_merged_prs_are_respected(self):
        self.publish()
        for state in ("CLOSED", "MERGED"):
            self.pr["state"] = state
            self.checkout()
            self.publish()
        self.assertEqual((self.creates, self.dispatches), (1, 1))

    def modify_remote_branch(self, path, text):
        edit = self.root / "edit"
        self.git("clone", "--branch", BRANCH, str(self.origin), str(edit), cwd=self.root)
        self.git("config", "user.name", "Test", cwd=edit)
        self.git("config", "user.email", "test@example.invalid", cwd=edit)
        (edit / path).write_text(text)
        self.git("add", path, cwd=edit)
        self.git("commit", "-m", "tamper", cwd=edit)
        self.git("push", "origin", BRANCH, cwd=edit)

    def orphan(self):
        self.fail_create = True
        with self.assertRaises(RuntimeError):
            self.publish()
        self.fail_create = False

    def test_unrelated_file_on_orphan_branch_is_rejected(self):
        self.orphan()
        self.modify_remote_branch("unrelated.txt", "modified\n")
        self.checkout()
        with self.assertRaisesRegex(ValueError, "unexpected changed files"):
            self.publish()
        self.assertEqual(self.creates, 0)

    def test_unrelated_property_on_orphan_branch_is_rejected(self):
        self.orphan()
        self.modify_remote_branch("gradle.properties", PROPERTIES.replace("30.0.100", "30.0.200").replace("unchanged", "changed"))
        self.checkout()
        with self.assertRaisesRegex(ValueError, "unrelated Gradle properties"):
            self.publish()

    def test_mismatched_target_on_orphan_branch_is_rejected(self):
        self.orphan()
        self.modify_remote_branch("gradle.properties", PROPERTIES.replace("30.0.100", "30.0.300"))
        self.checkout()
        with self.assertRaisesRegex(ValueError, "different target"):
            self.publish()

    def test_unrelated_staged_file_is_not_published(self):
        (self.repo / "unrelated.txt").write_text("new\n")
        self.git("add", "unrelated.txt")
        with self.assertRaisesRegex(ValueError, "unrelated staged files"):
            self.publish()
        self.assertEqual(self.creates, 0)

    def test_unrelated_property_in_new_update_is_not_published(self):
        path = self.repo / "gradle.properties"
        path.write_text(path.read_text().replace("other.setting=unchanged", "other.setting=changed"))
        with self.assertRaisesRegex(ValueError, "unrelated Gradle properties"):
            self.publish()
        self.assertEqual((self.creates, self.dispatches), (0, 0))

    def test_new_update_cannot_add_blank_lines(self):
        path = self.repo / "gradle.properties"
        path.write_bytes(b"\n" + path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "unrelated Gradle properties"):
            self.publish()
        self.assertEqual(self.creates, 0)

    def test_new_update_cannot_convert_line_endings(self):
        path = self.repo / "gradle.properties"
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        with self.assertRaisesRegex(ValueError, "unrelated Gradle properties"):
            self.publish()
        self.assertEqual(self.creates, 0)

    def test_crlf_update_is_preserved_in_new_and_reused_branch(self):
        path = self.seed / "gradle.properties"
        path.write_bytes(PROPERTIES.replace("\n", "\r\n").encode())
        self.git("add", "gradle.properties", cwd=self.seed)
        self.git("commit", "-m", "use CRLF", cwd=self.seed)
        self.git("push", "origin", "main", cwd=self.seed)
        self.checkout()
        self.publish()
        published = self.git("show", f"{BRANCH}:gradle.properties", cwd=self.origin, raw=True)
        self.assertEqual(published, PROPERTIES.replace("30.0.100", "30.0.200").replace("\n", "\r\n"))
        self.checkout()
        self.publish()
        self.assertEqual((self.creates, self.dispatches), (1, 1))

    def test_new_update_requires_report_to_match_original_pins(self):
        report = {"branch": BRANCH, "changes": [{"property": "duckdetector.android.ndk", "from": "29.0.100", "to": "30.0.200"}]}
        with self.assertRaisesRegex(ValueError, "checked-out base pins"):
            self.publish(report)
        self.assertEqual(self.creates, 0)

    def test_wrong_staged_target_set_is_not_published(self):
        (self.repo / "gradle.properties").write_text(PROPERTIES.replace("30.0.100", "30.0.300"))
        with self.assertRaisesRegex(ValueError, "Staged properties"):
            self.publish()
        self.assertEqual(self.creates, 0)

    def test_existing_open_pr_recovers_ci_after_base_advances(self):
        self.fail_dispatch = True
        with self.assertRaises(RuntimeError):
            self.publish()
        (self.seed / "unrelated.txt").write_text("new upstream content\n")
        self.git("add", "unrelated.txt", cwd=self.seed)
        self.git("commit", "-m", "advance main", cwd=self.seed)
        self.git("push", "origin", "main", cwd=self.seed)
        self.fail_dispatch = False
        self.checkout()
        self.publish()
        self.assertEqual((self.creates, self.dispatches), (1, 1))

    def test_noop_needs_no_api(self):
        PUBLISHER.publish({"branch": "", "changes": []}, self.body, "main",
                          lambda *args: self.fail("No-op must not invoke any commands"))


if __name__ == "__main__":
    unittest.main()
