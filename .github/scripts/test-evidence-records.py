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

"""Self-test for check-evidence-records.py using synthetic repository trees."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

CHECKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-evidence-records.py")

FIELDS = {
    "Observable signal": "A property value.",
    "Producing subsystem": "init's property service.",
    "Mechanism": "init copies androidboot.* into ro.boot.*.",
    "References": "system/core init/property_service.cpp.",
    "Applicability": "Every Android release this app supports.",
    "Visibility limits": "The property context must be readable by apps.",
    "Result states": "Detected, not detected, unavailable.",
    "Interpretation": "A warning; the value alone does not prove modification.",
}


def record(title: str = "Demo", status: str = "reviewed", **overrides: str | None) -> str:
    fields = dict(FIELDS)
    fields.update(overrides)
    lines = [f"# {title} evidence record", "", f"Status: {status}", "", "## Signals", "", "### Property value", ""]
    for name, value in fields.items():
        if value is not None:
            lines.append(f"- {name}: {value}")
    return "\n".join(lines) + "\n"


class EvidenceRecordCheckerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = self._directory.name
        self.write("feature/demo/detector/build.gradle.kts", "")
        self.write("capability/shared/data/build.gradle.kts", "")

    def tearDown(self) -> None:
        self._directory.cleanup()

    def write(self, relative_path: str, text: str) -> None:
        path = os.path.join(self.root, relative_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, CHECKER, "--repo-root", self.root],
                              capture_output=True, text=True, check=False)

    def assert_rejected(self, expected_message: str) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(expected_message, result.stderr)

    def write_both(self, demo: str, shared: str | None = None) -> None:
        self.write("feature/demo/EVIDENCE.md", demo)
        self.write("capability/shared/EVIDENCE.md", shared if shared is not None else record("Shared"))

    def test_accepts_complete_records(self) -> None:
        self.write_both(record())
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2 units, 2 signal entries, 0 discovery-only", result.stdout)

    def test_ignores_feature_directories_without_a_detector_module(self) -> None:
        self.write("feature/dashboard/ui/build.gradle.kts", "")
        self.write_both(record())
        self.assertEqual(self.run_checker().returncode, 0)

    def test_rejects_a_missing_record(self) -> None:
        self.write("capability/shared/EVIDENCE.md", record("Shared"))
        self.assert_rejected("feature/demo has no EVIDENCE.md")

    def test_rejects_a_missing_field(self) -> None:
        self.write_both(record(**{"Visibility limits": None}))
        self.assert_rejected("signal 'Property value' needs exactly one '- Visibility limits:' line")

    def test_rejects_an_empty_field(self) -> None:
        self.write_both(record(**{"Interpretation": ""}))
        self.assert_rejected("signal 'Property value' leaves 'Interpretation' empty")

    def test_rejects_references_without_a_primary_source(self) -> None:
        self.write_both(record(**{"References": "A forum thread."}))
        self.assert_rejected("signal 'Property value' cites no primary source")

    def test_accepts_a_declared_discovery_basis(self) -> None:
        self.write_both(record(**{"References": "Discovery only: the tool's observed behaviour."}))
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 discovery-only", result.stdout)

    def test_joins_a_field_that_continues_on_indented_lines(self) -> None:
        self.write_both(record(**{"References": "The platform keeps this in\n  system/core init/property_service.cpp."}))
        self.assertEqual(self.run_checker().returncode, 0)

    def test_rejects_a_draft(self) -> None:
        self.write_both(record(status="draft"))
        self.assert_rejected("feature/demo/EVIDENCE.md is still a draft")

    def test_rejects_a_record_without_signals(self) -> None:
        self.write_both("# Demo evidence record\n\nStatus: reviewed\n\n## Signals\n\nNothing yet.\n")
        self.assert_rejected("lists no signal under '## Signals'")

    def test_rejects_a_record_without_the_heading(self) -> None:
        self.write_both(record().replace("# Demo evidence record", "# Demo notes"))
        self.assert_rejected("must open with a '# ... evidence record' heading")


if __name__ == "__main__":
    unittest.main()
