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

"""Self-test for new_detector.py, run against copies of the repository's real registration files.

CI also scaffolds a detector in the real checkout and builds it; this test pins what the script
writes and where.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(SCRIPTS)
SCAFFOLD = os.path.join(SCRIPTS, "new_detector.py")
JNI_CHECKER = os.path.join(REPO, ".github", "scripts", "check-jni-contracts.py")
EVIDENCE_CHECKER = os.path.join(REPO, ".github", "scripts", "check-evidence-records.py")
CATALOG = "sdk/runtime/src/main/kotlin/com/eltavine/duckdetector/sdk/DetectorCatalog.kt"
FEATURES = "app/src/main/java/com/eltavine/duckdetector/ui/DetectorFeatures.kt"
NATIVE_CMAKE = "sdk/runtime/src/main/cpp/CMakeLists.txt"
NATIVE_POLICY = ".github/policies/native-boundaries.json"
DETECTOR_OBJECT = re.compile(r"\bobject\s+(\w+)\s*:\s*Detector<")
DETECTOR_ID = re.compile(r'DetectorId\("([^"]+)"\)')


class NewDetectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = self._directory.name
        for relative in (CATALOG, FEATURES, NATIVE_CMAKE, NATIVE_POLICY):
            self.copy(relative)
        feature = os.path.join(REPO, "feature")
        for unit in sorted(os.listdir(feature)):
            detector = os.path.join(feature, unit, "detector")
            if not os.path.isfile(os.path.join(detector, "build.gradle.kts")):
                continue
            self.copy(os.path.relpath(os.path.join(detector, "build.gradle.kts"), REPO))
            for directory, _, files in os.walk(os.path.join(detector, "src", "main")):
                for name in files:
                    self.copy(os.path.relpath(os.path.join(directory, name), REPO))
        self.before = self.snapshot()

    def tearDown(self) -> None:
        self._directory.cleanup()

    def copy(self, relative: str) -> None:
        target = os.path.join(self.root, relative)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(os.path.join(REPO, relative), target)

    def snapshot(self) -> dict[str, str]:
        files = {}
        for directory, _, names in os.walk(self.root):
            for name in names:
                path = os.path.join(directory, name)
                with open(path, encoding="utf-8") as handle:
                    files[os.path.relpath(path, self.root)] = handle.read()
        return files

    def scaffold(self, *arguments: str, description: str = "looks for demo evidence") -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, SCAFFOLD, *arguments, "--description", description,
                               "--repo-root", self.root], capture_output=True, text=True, check=False)

    def read(self, relative: str) -> str:
        with open(os.path.join(self.root, relative), encoding="utf-8") as handle:
            return handle.read()

    def list_entries(self, relative: str, opener: str) -> list[str]:
        lines = self.read(relative).split("\n")
        start = lines.index(opener) + 1
        end = next(index for index in range(start, len(lines)) if lines[index].startswith("    )"))
        return [line.strip().rstrip(",") for line in lines[start:end]]

    def catalog_ids(self) -> list[str]:
        ids = {}
        for relative, text in self.snapshot().items():
            detector, identity = DETECTOR_OBJECT.search(text), DETECTOR_ID.search(text)
            if relative.startswith("feature/") and detector and identity:
                ids[detector.group(1)] = identity.group(1)
        return [ids[entry] for entry in self.list_entries(CATALOG, "    public val all: List<Detector<*, *>> = listOf(")]

    def changes(self) -> tuple[set[str], set[str]]:
        after = self.snapshot()
        created = set(after) - set(self.before)
        modified = {path for path in self.before if after.get(path) != self.before[path]}
        return created, modified

    def test_creates_five_modules_and_touches_only_the_catalog(self) -> None:
        result = self.scaffold("demo")

        self.assertEqual(result.returncode, 0, result.stderr)
        created, modified = self.changes()
        self.assertTrue(all(path.startswith("feature/demo/") for path in created), created)
        self.assertEqual({path.split("/")[2] for path in created if path.endswith("build.gradle.kts")},
                         {"domain", "data", "presentation", "detector", "ui"})
        self.assertEqual(modified, {CATALOG})

    def test_catalog_keeps_its_first_two_detectors_and_orders_the_rest_by_id(self) -> None:
        first_two = self.catalog_ids()[:2]
        for name in ("aaaa", "mmmm", "zzzz"):
            self.assertEqual(self.scaffold(name).returncode, 0)

        ids = self.catalog_ids()
        self.assertEqual(ids[:2], first_two)
        self.assertEqual(ids[2:], sorted(ids[2:]))
        self.assertTrue({"aaaa", "mmmm", "zzzz"} <= set(ids))

    def test_the_card_is_exported_under_the_name_the_app_generates_and_imports_stay_sorted(self) -> None:
        self.assertEqual(self.scaffold("demo").returncode, 0)

        feature = self.read("feature/demo/ui/src/main/kotlin/com/eltavine/duckdetector/features/demo/ui/"
                            "DemoDetectorFeature.kt")
        self.assertIn("\nval detectorFeature: DetectorFeature = CardDetectorFeature(DemoDetector)", feature)
        imports = [line for line in self.read(CATALOG).split("\n") if line.startswith("import ")]
        self.assertEqual(imports, sorted(imports))

    def test_names_derive_from_the_class_name(self) -> None:
        self.assertEqual(self.scaffold("playdemo", "--class-name", "PlayDemo").returncode, 0)

        detector = self.read("feature/playdemo/detector/src/main/kotlin/com/eltavine/duckdetector/features/"
                             "playdemo/detector/PlayDemoDetector.kt")
        mapper = self.read("feature/playdemo/presentation/src/main/kotlin/com/eltavine/duckdetector/features/"
                           "playdemo/presentation/PlayDemoCardModelMapper.kt")
        self.assertIn('DetectorId("play_demo")', detector)
        self.assertIn(" * Play Demo: looks for demo evidence.", detector)
        self.assertIn('const val TITLE = "Play Demo"', mapper)

    def test_generated_sources_are_complete(self) -> None:
        self.assertEqual(self.scaffold("demo", "--native").returncode, 0)

        created, _ = self.changes()
        for path in created:
            text = self.read(path)
            self.assertNotIn("{{", text, path)
            if path.endswith((".kt", ".kts", ".cpp")):
                self.assertTrue(text.startswith("/*\n * Copyright "), path)

    def test_writes_a_draft_evidence_record_that_ci_rejects_until_researched(self) -> None:
        self.assertEqual(self.scaffold("demo").returncode, 0)

        record = self.read("feature/demo/EVIDENCE.md")
        self.assertTrue(record.startswith("# Demo evidence record\n"), record)
        self.assertIn("Status: draft", record)
        evidence = subprocess.run([sys.executable, EVIDENCE_CHECKER, "--repo-root", self.root],
                                  capture_output=True, text=True, check=False)
        self.assertEqual(evidence.returncode, 1)
        self.assertIn("feature/demo/EVIDENCE.md is still a draft", evidence.stderr)

    def test_native_unit_is_registered_and_its_jni_symbol_binds(self) -> None:
        result = self.scaffold("demo", "--native")

        self.assertEqual(result.returncode, 0, result.stderr)
        _, modified = self.changes()
        self.assertEqual(modified, {CATALOG, NATIVE_CMAKE, NATIVE_POLICY})
        registry = self.read(NATIVE_CMAKE)
        self.assertRegex(registry, r"\n    demo +feature/demo/data\n\)")
        unit = json.loads(self.read(NATIVE_POLICY))["units"]["demo"]
        self.assertEqual(unit, {"path": "demo", "owner": ":feature:demo:data", "target": "duckdetector_demo",
                                "may_include": ["common"]})
        self.assertTrue(os.path.isfile(os.path.join(self.root, "feature/demo/data/src/main/cpp/demo/CMakeLists.txt")))
        jni = subprocess.run([sys.executable, JNI_CHECKER, "--repo-root", self.root],
                             capture_output=True, text=True, check=False)
        self.assertEqual(jni.returncode, 0, jni.stderr)
        self.assertIn("1 bindings", jni.stdout)

    def test_rejects_conflicts_without_writing(self) -> None:
        self.assertEqual(self.scaffold("demo").returncode, 0)
        self.before = self.snapshot()
        existing_id = self.catalog_ids()[0]

        for arguments in (("demo",), ("other", "--class-name", "Demo"), ("other", "--id", existing_id)):
            result = self.scaffold(*arguments)
            self.assertEqual(result.returncode, 2, arguments)
            self.assertIn("already", result.stderr)
        self.assertEqual(self.changes(), (set(), set()))

    def test_rejects_invalid_names_and_text(self) -> None:
        cases = [
            (("Demo",), "name"),
            (("demo_probe",), "name"),
            (("object",), "Kotlin keyword"),
            (("demo", "--class-name", "demo"), "class name"),
            (("demo", "--id", "Demo"), "id"),
            (("demo", "--title", 'Say "hi"'), "title"),
        ]
        for arguments, message in cases:
            result = self.scaffold(*arguments)
            self.assertEqual(result.returncode, 2, arguments)
            self.assertIn(message, result.stderr)
        self.assertEqual(self.scaffold("demo", description="ends a comment */").returncode, 2)
        self.assertEqual(self.changes(), (set(), set()))


if __name__ == "__main__":
    unittest.main()
