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

"""Create a detector: its five modules under feature/<name>/ and its one registration line.

    python3 scripts/new_detector.py NAME --description "what it looks for and why that is evidence"
        [--class-name ClassName] [--id detector_id] [--title "Card title"] [--native]

NAME is the directory and package segment, such as "debugger". The new detector builds and passes
the boundary, dependency, touch point and native checks as generated. Until its probe observes the
device it reports "Not evaluated", so an unfinished detector never reads as a clean result.

The registration is the detector's entry in DetectorCatalog, which fixes the order scans start.
The app generates its list of dashboard cards from the ui modules, so it needs no entry.

--native adds a native unit with its JNI bridge, and registers it in the SDK's native build and in
the native boundary policy. Nothing outside feature/<name>/ changes except those registrations.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import os
import re
import sys

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "detector_template")
PACKAGE_ROOT = "com.eltavine.duckdetector.features"
CATALOG = "sdk/runtime/src/main/kotlin/com/eltavine/duckdetector/sdk/DetectorCatalog.kt"
NATIVE_CMAKE = "sdk/runtime/src/main/cpp/CMakeLists.txt"
NATIVE_POLICY = ".github/policies/native-boundaries.json"

CATALOG_LIST = ("    public val all: List<Detector<*, *>> = listOf(", "    )")
NATIVE_REGISTRY = ("set(DUCKDETECTOR_NATIVE_UNITS", ")")
# DetectorCatalog starts bootloader and TEE first; every other detector follows by id.
CATALOG_FIXED_ENTRIES = 2

# Template, and its target below feature/<name>/.
FILES = [
    ("EVIDENCE.md.tmpl", "EVIDENCE.md"),
    ("domain/build.gradle.kts.tmpl", "domain/build.gradle.kts"),
    ("domain/Report.kt.tmpl", "domain/src/main/kotlin/{package_path}/domain/{Class}Report.kt"),
    ("domain/ReportStatus.kt.tmpl", "domain/src/main/kotlin/{package_path}/domain/{Class}ReportStatus.kt"),
    ("domain/ReportStatusTest.kt.tmpl", "domain/src/test/kotlin/{package_path}/domain/{Class}ReportStatusTest.kt"),
    ("data/build.gradle.kts.tmpl", "data/build.gradle.kts"),
    ("data/Repository.kt.tmpl", "data/src/main/kotlin/{package_path}/data/repository/{Class}Repository.kt"),
    ("presentation/build.gradle.kts.tmpl", "presentation/build.gradle.kts"),
    ("presentation/CardModel.kt.tmpl",
     "presentation/src/main/kotlin/{package_path}/presentation/model/{Class}CardModel.kt"),
    ("presentation/CardModelMapper.kt.tmpl",
     "presentation/src/main/kotlin/{package_path}/presentation/{Class}CardModelMapper.kt"),
    ("presentation/DetectorReport.kt.tmpl",
     "presentation/src/main/kotlin/{package_path}/presentation/{Class}DetectorReport.kt"),
    ("presentation/CardModelMapperTest.kt.tmpl",
     "presentation/src/test/kotlin/{package_path}/presentation/{Class}CardModelMapperTest.kt"),
    ("detector/build.gradle.kts.tmpl", "detector/build.gradle.kts"),
    ("detector/Detector.kt.tmpl", "detector/src/main/kotlin/{package_path}/detector/{Class}Detector.kt"),
    ("ui/build.gradle.kts.tmpl", "ui/build.gradle.kts"),
    ("ui/DetectorFeature.kt.tmpl", "ui/src/main/kotlin/{package_path}/ui/{Class}DetectorFeature.kt"),
    ("ui/DetectorCard.kt.tmpl", "ui/src/main/kotlin/{package_path}/ui/card/{Class}DetectorCard.kt"),
]
# With --native these replace the data layer's build file and repository and add the native unit.
NATIVE_FILES = [
    ("native/build.gradle.kts.tmpl", "data/build.gradle.kts"),
    ("native/Repository.kt.tmpl", "data/src/main/kotlin/{package_path}/data/repository/{Class}Repository.kt"),
    ("native/NativeBridge.kt.tmpl", "data/src/main/kotlin/{package_path}/data/native/{Class}NativeBridge.kt"),
    ("native/NativeSnapshot.kt.tmpl", "data/src/main/kotlin/{package_path}/data/native/{Class}NativeSnapshot.kt"),
    ("native/NativeBridgeTest.kt.tmpl",
     "data/src/test/kotlin/{package_path}/data/native/{Class}NativeBridgeTest.kt"),
    ("native/CMakeLists.txt.tmpl", "data/src/main/cpp/{name}/CMakeLists.txt"),
    ("native/native_bridge.cpp.tmpl", "data/src/main/cpp/{name}/native_bridge.cpp"),
]
LICENSED_SUFFIXES = (".kt", ".kts", ".cpp")
LICENSE = """/*
 * Copyright {year} Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

"""

NAME_PATTERN = re.compile(r"[a-z][a-z0-9]*")
CLASS_PATTERN = re.compile(r"[A-Z][A-Za-z0-9]*")
ID_PATTERN = re.compile(r"[a-z][a-z0-9_]*")
# Titles become Kotlin string literals and descriptions KDoc text.
TEXT_PATTERN = re.compile(r"[^\"\\$\n*]+")
KOTLIN_KEYWORDS = {"as", "break", "class", "continue", "do", "else", "false", "for", "fun", "if", "in", "interface",
                   "is", "null", "object", "package", "return", "super", "this", "throw", "true", "try", "typealias",
                   "typeof", "val", "var", "when", "while"}
PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")
WORD_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
DETECTOR_OBJECT = re.compile(r"\bobject\s+(\w+)\s*:\s*Detector<")
DETECTOR_ID = re.compile(r'DetectorId\("([^"]+)"\)')


class ScaffoldError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class Spec:
    name: str
    class_name: str
    detector_id: str
    title: str
    description: str
    native: bool

    @property
    def package(self) -> str:
        return f"{PACKAGE_ROOT}.{self.name}"

    def placeholders(self) -> dict[str, str]:
        bridge = f"{self.package}.data.native.{self.class_name}NativeBridge"
        return {
            "package": self.package,
            "name": self.name,
            "Class": self.class_name,
            "id": self.detector_id,
            "title": self.title,
            "subtitle": f"{self.title} probes",
            "description": self.description,
            # Static JNI naming; the name patterns exclude the underscores that would need escaping.
            "jni": "Java_" + bridge.replace(".", "_"),
        }


def parse_spec(argv: list[str]) -> tuple[Spec, str]:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("name", help="directory and package segment, such as debugger")
    parser.add_argument("--description", required=True,
                        help="what the detector looks for and why that is evidence; opens the detector's KDoc")
    parser.add_argument("--class-name", help="class name prefix; defaults to NAME capitalised")
    parser.add_argument("--id", help="stable detector id; defaults to the class name in snake_case")
    parser.add_argument("--title", help="card title; defaults to the class name split into words")
    parser.add_argument("--native", action="store_true", help="add a native unit with a JNI bridge")
    parser.add_argument("--repo-root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    arguments = parser.parse_args(argv)

    name = arguments.name
    class_name = arguments.class_name or name[:1].upper() + name[1:]
    detector_id = arguments.id or WORD_BOUNDARY.sub("_", class_name).lower()
    title = arguments.title or WORD_BOUNDARY.sub(" ", class_name)
    description = arguments.description.strip()
    if description and not description.endswith("."):
        description += "."
    if not NAME_PATTERN.fullmatch(name) or name in KOTLIN_KEYWORDS:
        raise ScaffoldError(f"name {name!r} must be lowercase letters and digits and not a Kotlin keyword")
    if not CLASS_PATTERN.fullmatch(class_name):
        raise ScaffoldError(f"class name {class_name!r} must be letters and digits starting with a capital")
    if not ID_PATTERN.fullmatch(detector_id):
        raise ScaffoldError(f"id {detector_id!r} must be lowercase letters, digits and underscores")
    for label, text in (("title", title), ("description", description)):
        if not TEXT_PATTERN.fullmatch(text):
            raise ScaffoldError(f"{label} {text!r} must be one line without quotes, backslashes, '$' or '*'")
    spec = Spec(name, class_name, detector_id, title, description, arguments.native)
    return spec, os.path.abspath(arguments.repo_root)


def existing_detectors(repo_root: str) -> dict[str, str]:
    """Detector object name to id, for every feature/<name>/detector."""
    found: dict[str, str] = {}
    feature = os.path.join(repo_root, "feature")
    for unit in sorted(os.listdir(feature)) if os.path.isdir(feature) else []:
        for directory, _, files in os.walk(os.path.join(feature, unit, "detector", "src", "main")):
            for file_name in sorted(files):
                if not file_name.endswith(".kt"):
                    continue
                with open(os.path.join(directory, file_name), encoding="utf-8") as handle:
                    text = handle.read()
                detector, identity = DETECTOR_OBJECT.search(text), DETECTOR_ID.search(text)
                if detector and identity:
                    found[detector.group(1)] = identity.group(1)
    return found


def render(template: str, values: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        if match.group(1) not in values:
            raise ScaffoldError(f"template placeholder {match.group(0)} has no value")
        return values[match.group(1)]

    return PLACEHOLDER.sub(replace, template)


def generated_files(spec: Spec) -> dict[str, str]:
    values = spec.placeholders()
    year = str(datetime.date.today().year)
    files: dict[str, str] = {}
    for template, target in FILES + (NATIVE_FILES if spec.native else []):
        with open(os.path.join(TEMPLATE_DIR, template), encoding="utf-8") as handle:
            content = render(handle.read(), values)
        path = f"feature/{spec.name}/" + target.format(
            package_path=spec.package.replace(".", "/"), Class=spec.class_name, name=spec.name)
        files[path] = (LICENSE.format(year=year) + content) if path.endswith(LICENSED_SUFFIXES) else content
    return files


def list_bounds(lines: list[str], bounds: tuple[str, str], source: str) -> tuple[int, int]:
    opener, closer = bounds
    if opener not in lines:
        raise ScaffoldError(f"{source} no longer has the line {opener.strip()!r}; update new_detector.py")
    start = lines.index(opener)
    for end in range(start + 1, len(lines)):
        if lines[end] == closer:
            return start + 1, end
    raise ScaffoldError(f"{source}: {opener.strip()!r} is not closed by {closer.strip()!r}")


def add_import(lines: list[str], statement: str, source: str) -> None:
    imports = [index for index, line in enumerate(lines) if line.startswith("import ")]
    if not imports or statement in lines:
        raise ScaffoldError(f"{source}: cannot add {statement!r}")
    lines.insert(next((index for index in imports if lines[index] > statement), imports[-1] + 1), statement)


def register_in_catalog(text: str, spec: Spec, ids: dict[str, str]) -> str:
    lines = text.split("\n")
    add_import(lines, f"import {spec.package}.detector.{spec.class_name}Detector", CATALOG)
    first, end = list_bounds(lines, CATALOG_LIST, CATALOG)
    position = first + CATALOG_FIXED_ENTRIES
    while position < end:
        entry = lines[position].strip().rstrip(",")
        if entry not in ids:
            raise ScaffoldError(f"{CATALOG}: no detector object named {entry} under feature/*/detector")
        if ids[entry] > spec.detector_id:
            break
        position += 1
    lines.insert(position, f"        {spec.class_name}Detector,")
    return "\n".join(lines)


def register_native_unit(text: str, spec: Spec) -> str:
    lines = text.split("\n")
    first, end = list_bounds(lines, NATIVE_REGISTRY, NATIVE_CMAKE)
    units = [lines[index].split() for index in range(first, end)]
    if any(len(unit) != 2 for unit in units):
        raise ScaffoldError(f"{NATIVE_CMAKE}: every registry line must be '<unit> <owner directory>'")
    if spec.name in {unit for unit, _ in units}:
        raise ScaffoldError(f"a native unit named {spec.name} already exists")
    units.append([spec.name, f"feature/{spec.name}/data"])
    width = max(len(unit) for unit, _ in units) + 1
    lines[first:end] = [f"    {unit.ljust(width)}{owner}" for unit, owner in units]
    return "\n".join(lines)


def register_native_policy(text: str, spec: Spec) -> str:
    document = json.loads(text)
    if spec.name in document["units"]:
        raise ScaffoldError(f"{NATIVE_POLICY} already has a unit named {spec.name}")
    document["units"][spec.name] = {
        "path": spec.name,
        "owner": f":feature:{spec.name}:data",
        "target": f"duckdetector_{spec.name}",
        "may_include": ["common"],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def plan(spec: Spec, repo_root: str) -> tuple[dict[str, str], dict[str, str]]:
    """The files to create and the registrations to rewrite, computed before anything is written."""
    if os.path.exists(os.path.join(repo_root, "feature", spec.name)):
        raise ScaffoldError(f"feature/{spec.name} already exists")
    ids = existing_detectors(repo_root)
    if f"{spec.class_name}Detector" in ids:
        raise ScaffoldError(f"a detector object named {spec.class_name}Detector already exists")
    if spec.detector_id in ids.values():
        raise ScaffoldError(f"a detector already has the id {spec.detector_id}")

    def read(relative: str) -> str:
        with open(os.path.join(repo_root, relative), encoding="utf-8") as handle:
            return handle.read()

    edits = {CATALOG: register_in_catalog(read(CATALOG), spec, ids)}
    if spec.native:
        edits[NATIVE_CMAKE] = register_native_unit(read(NATIVE_CMAKE), spec)
        edits[NATIVE_POLICY] = register_native_policy(read(NATIVE_POLICY), spec)
    return generated_files(spec), edits


def main(argv: list[str]) -> int:
    try:
        spec, repo_root = parse_spec(argv)
        created, edits = plan(spec, repo_root)
    except ScaffoldError as error:
        print(f"new_detector: {error}", file=sys.stderr)
        return 2
    for relative, content in {**created, **edits}.items():
        path = os.path.join(repo_root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    print(f"Created feature/{spec.name}/ ({len(created)} files) and registered {spec.class_name}Detector in:")
    for relative in edits:
        print(f"  {relative}")
    print(f"""
Next:
  1. Research the signal and record it in feature/{spec.name}/EVIDENCE.md (AGENTS.md sections 2 and 12);
     CI rejects the record while it is a draft.
  2. Write the probe in {spec.class_name}Repository{" and native_bridge.cpp" if spec.native else ""}, and the
     verdict rules in {spec.class_name}ReportStatus.kt. Until the probe observes the device, the card
     reads "Not evaluated".
  3. ./gradlew :feature:{spec.name}:domain:test :feature:{spec.name}:presentation:test
  4. ./gradlew unitTest :app:assembleDebug buildHealth
See docs/guides/adding-a-detector.md.""")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
