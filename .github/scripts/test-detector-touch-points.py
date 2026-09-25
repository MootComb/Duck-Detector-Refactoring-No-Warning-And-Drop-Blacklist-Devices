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

"""Self-test for check-detector-touch-points.py using synthetic repositories."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

CHECKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-detector-touch-points.py")
CATALOG = "sdk/runtime/src/main/kotlin/Catalog.kt"
CARDS = "app/src/main/kotlin/Cards.kt"


class DetectorTouchPointCheckerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = self._directory.name
        self.policy = {
            "schema_version": 1,
            "registrations": [
                {"path": CATALOG, "layer": "detector", "reason": "the detector list"},
                {"path": CARDS, "layer": "ui", "reason": "the dashboard cards"},
            ],
            "indexes": [{"path": "native/CMakeLists.txt", "reason": "the native unit registry"}],
            "exceptions": [],
        }
        for detector in ("alpha", "beta"):
            self.write(f"feature/{detector}/detector/build.gradle.kts", "")
            self.write(f"feature/{detector}/detector/src/Detector.kt",
                       f"import com.eltavine.duckdetector.features.{detector}.data.Repository\n")
        self.write("feature/dashboard/ui/build.gradle.kts", "")
        self.write(CATALOG, "import com.eltavine.duckdetector.features.alpha.detector.AlphaDetector\n"
                            "import com.eltavine.duckdetector.features.beta.detector.BetaDetector\n")
        self.write(CARDS, "import com.eltavine.duckdetector.features.alpha.ui.AlphaCard\n"
                          "import com.eltavine.duckdetector.features.beta.ui.BetaCard\n")
        self.write("native/CMakeLists.txt", "set(UNITS alpha feature/alpha/data)\n")

    def tearDown(self) -> None:
        self._directory.cleanup()

    def write(self, relative_path: str, content: str) -> None:
        path = os.path.join(self.root, relative_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        self.write(".github/policies/detector-touch-points.json", json.dumps(self.policy))
        return subprocess.run([sys.executable, CHECKER, "--repo-root", self.root],
                              capture_output=True, text=True, check=False)

    def assert_rejected(self, *expected_messages: str) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for message in expected_messages:
            self.assertIn(message, result.stderr)

    def assert_policy_error(self, expected_message: str) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(expected_message, result.stderr)

    def add_exception(self, path: str, detectors: list[str], reason: str = "reviewed coupling") -> None:
        self.policy["exceptions"].append({"path": path, "detectors": detectors, "reason": reason})

    def test_accepts_detectors_named_only_by_their_own_directory_and_the_reviewed_places(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2 detectors, 2 registrations, 1 indexes, 0 exceptions", result.stdout)

    def test_rejects_central_code_naming_a_detector(self) -> None:
        self.write("app/src/main/kotlin/Shell.kt", "import com.eltavine.duckdetector.features.beta.data.Probe\n")
        self.assert_rejected("app/src/main/kotlin/Shell.kt names the beta detector outside feature/beta/")

    def test_rejects_module_paths_and_directories_of_a_detector(self) -> None:
        self.write("app/build.gradle.kts", 'implementation(project(":feature:alpha:data"))\n')
        self.write("scripts/tool.py", 'ROOT = "feature/beta/data"\n')
        self.assert_rejected("app/build.gradle.kts names the alpha detector", "scripts/tool.py names the beta detector")

    def test_rejects_one_detector_naming_another(self) -> None:
        self.write("feature/beta/ui/src/Card.kt", "import com.eltavine.duckdetector.features.alpha.presentation.Model\n")
        self.assert_rejected("feature/beta/ui/src/Card.kt names the alpha detector outside feature/alpha/")

    def test_exception_allows_only_the_detectors_it_lists(self) -> None:
        self.write("app/src/main/kotlin/Shell.kt", "import com.eltavine.duckdetector.features.alpha.data.A\n"
                                                   "import com.eltavine.duckdetector.features.beta.data.B\n")
        self.add_exception("app/src/main/kotlin/Shell.kt", ["alpha"])
        result = self.run_checker()
        self.assertEqual(result.returncode, 1)
        self.assertIn("Shell.kt names the beta detector", result.stderr)
        self.assertNotIn("Shell.kt names the alpha detector", result.stderr)

    def test_rejects_stale_exception(self) -> None:
        self.write("app/src/main/kotlin/Shell.kt", "import com.eltavine.duckdetector.features.alpha.data.A\n")
        self.add_exception("app/src/main/kotlin/Shell.kt", ["alpha", "beta"])
        self.assert_rejected("exception app/src/main/kotlin/Shell.kt -> beta is stale")

    def test_rejects_a_registration_that_misses_a_detector(self) -> None:
        self.write(CARDS, "import com.eltavine.duckdetector.features.alpha.ui.AlphaCard\n")
        self.assert_rejected(f"{CARDS} does not register the beta detector through its ui layer")

    def test_rejects_a_registration_that_names_the_wrong_layer(self) -> None:
        self.write(CATALOG, "import com.eltavine.duckdetector.features.alpha.detector.AlphaDetector\n"
                            "import com.eltavine.duckdetector.features.beta.data.BetaRepository\n")
        self.assert_rejected(f"{CATALOG} does not register the beta detector through its detector layer")

    def test_rejects_missing_registration_and_index_files(self) -> None:
        os.remove(os.path.join(self.root, CATALOG))
        os.remove(os.path.join(self.root, "native/CMakeLists.txt"))
        self.assert_rejected(f"registration {CATALOG} does not exist", "index native/CMakeLists.txt does not exist")

    def test_ignores_documentation_and_features_that_are_not_detectors(self) -> None:
        self.write("docs/guide.md", "See com.eltavine.duckdetector.features.alpha.data and feature/beta/ui.\n")
        self.write("app/src/main/kotlin/Dashboard.kt", "import com.eltavine.duckdetector.features.dashboard.ui.X\n")
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_entries_without_a_reason(self) -> None:
        self.add_exception("app/src/main/kotlin/Shell.kt", ["alpha"], reason=" ")
        self.assert_policy_error("must state a reason")

    def test_rejects_a_path_listed_twice(self) -> None:
        self.add_exception(CARDS, ["alpha"])
        self.assert_policy_error("may be listed only once")

    def test_rejects_malformed_policy(self) -> None:
        del self.policy["indexes"]
        self.assert_policy_error("expected schema_version 1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
