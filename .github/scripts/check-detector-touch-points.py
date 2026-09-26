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

"""Keep every detector inside its own directory, except for a few reviewed places.

A detector is a feature unit with a detector layer, feature/<name>/detector. Outside
feature/<name>/, a file names a detector when it spells one of its packages
(com.eltavine.duckdetector.features.<name>.), module paths (:feature:<name>:) or directories
(feature/<name>/). Only three kinds of file may do that, each listed with a reason in
detector-touch-points.json:

- registrations, which must name every detector through the given layer;
- indexes, which tooling keeps and which may name any detector;
- exceptions, which may name only the detectors they list.

Markdown documentation is not checked. An exception that no longer names one of its detectors is
stale, so the list only ever shrinks when a coupling goes away.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import sys

POLICY_KEYS = {"schema_version", "registrations", "indexes", "exceptions"}
SKIPPED_DIRECTORIES = {".git", "build", ".gradle", ".cxx", ".idea", ".kotlin", "__pycache__", ".externalNativeBuild"}
SKIPPED_SUFFIXES = (".md", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico", ".jar", ".aar", ".apk", ".so",
                    ".keystore", ".jks", ".zip", ".DS_Store")


class PolicyError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class Policy:
    registrations: dict[str, str]
    indexes: set[str]
    exceptions: dict[str, set[str]]


def load_policy(path: str) -> Policy:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or set(document) != POLICY_KEYS or document["schema_version"] != 1:
        raise PolicyError(f"{path}: expected schema_version 1 with keys {sorted(POLICY_KEYS)}")

    def entries(key: str, fields: set[str]) -> list[dict]:
        values = document[key]
        if not isinstance(values, list):
            raise PolicyError(f"{key} must be a list")
        for entry in values:
            if not isinstance(entry, dict) or set(entry) != fields:
                raise PolicyError(f"each entry of {key} needs exactly {sorted(fields)}")
            if not isinstance(entry["reason"], str) or not entry["reason"].strip():
                raise PolicyError(f"{key} entry {entry.get('path')} must state a reason")
        paths = [entry["path"] for entry in values]
        if len(paths) != len(set(paths)):
            raise PolicyError(f"{key} lists a path twice")
        return values

    registrations = {entry["path"]: entry["layer"] for entry in entries("registrations", {"path", "layer", "reason"})}
    indexes = {entry["path"] for entry in entries("indexes", {"path", "reason"})}
    exceptions = {}
    for entry in entries("exceptions", {"path", "detectors", "reason"}):
        detectors = entry["detectors"]
        if not isinstance(detectors, list) or not detectors or not all(isinstance(item, str) for item in detectors):
            raise PolicyError(f"exception {entry['path']} must list the detectors it may name")
        exceptions[entry["path"]] = set(detectors)
    overlap = (set(registrations) & indexes) | (set(registrations) & set(exceptions)) | (indexes & set(exceptions))
    if overlap:
        raise PolicyError(f"a path may be listed only once across registrations, indexes and exceptions: {sorted(overlap)}")
    return Policy(registrations, indexes, exceptions)


def discover_detectors(repo_root: str) -> list[str]:
    feature = os.path.join(repo_root, "feature")
    if not os.path.isdir(feature):
        return []
    return sorted(name for name in os.listdir(feature)
                  if os.path.isfile(os.path.join(feature, name, "detector", "build.gradle.kts")))


def reference_pattern(detector: str) -> re.Pattern[str]:
    name = re.escape(detector)
    return re.compile(rf"com\.eltavine\.duckdetector\.features\.{name}\.|:feature:{name}:|feature/{name}/")


def iter_files(repo_root: str):
    for directory, subdirectories, files in os.walk(repo_root):
        subdirectories[:] = sorted(name for name in subdirectories if name not in SKIPPED_DIRECTORIES)
        for name in sorted(files):
            if name.endswith(SKIPPED_SUFFIXES):
                continue
            path = os.path.join(directory, name)
            yield os.path.relpath(path, repo_root).replace(os.sep, "/"), path


def check(repo_root: str, policy: Policy) -> tuple[list[str], str]:
    errors: list[str] = []
    detectors = discover_detectors(repo_root)
    patterns = {detector: reference_pattern(detector) for detector in detectors}
    named: dict[str, set[str]] = {}
    for relative, path in iter_files(repo_root):
        try:
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        except (UnicodeDecodeError, OSError):
            continue
        found = {detector for detector, pattern in patterns.items()
                 if not relative.startswith(f"feature/{detector}/") and pattern.search(text)}
        if found:
            named[relative] = found
    for relative, found in sorted(named.items()):
        if relative in policy.registrations or relative in policy.indexes:
            continue
        allowed = policy.exceptions.get(relative, set())
        for detector in sorted(found - allowed):
            errors.append(f"{relative} names the {detector} detector outside feature/{detector}/; keep the "
                          "coupling inside the detector, or record it in detector-touch-points.json with a reason")
    for relative, layer in sorted(policy.registrations.items()):
        if not os.path.isfile(os.path.join(repo_root, relative)):
            errors.append(f"registration {relative} does not exist")
            continue
        with open(os.path.join(repo_root, relative), encoding="utf-8") as handle:
            text = handle.read()
        for detector in detectors:
            if f"com.eltavine.duckdetector.features.{detector}.{layer}." not in text:
                errors.append(f"{relative} does not register the {detector} detector through its {layer} layer")
    for relative in sorted(policy.indexes):
        if not os.path.isfile(os.path.join(repo_root, relative)):
            errors.append(f"index {relative} does not exist")
    for relative, allowed in sorted(policy.exceptions.items()):
        for detector in sorted(allowed - named.get(relative, set())):
            errors.append(f"exception {relative} -> {detector} is stale; the file no longer names that detector")
    summary = (f"Detector touch points verified: {len(detectors)} detectors, {len(policy.registrations)} "
               f"registrations, {len(policy.indexes)} indexes, {len(policy.exceptions)} exceptions.")
    return errors, summary


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    parser.add_argument("--repo-root", default=default_root)
    arguments = parser.parse_args(argv)
    repo_root = os.path.abspath(arguments.repo_root)
    try:
        policy = load_policy(os.path.join(repo_root, ".github", "policies", "detector-touch-points.json"))
    except (OSError, PolicyError, json.JSONDecodeError) as error:
        print(f"detector touch point policy error: {error}", file=sys.stderr)
        return 2
    errors, summary = check(repo_root, policy)
    if errors:
        for error in errors:
            print(f"detector touch point violation: {error}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
