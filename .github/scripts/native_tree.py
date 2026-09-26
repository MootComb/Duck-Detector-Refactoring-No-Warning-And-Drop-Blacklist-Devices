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

"""The native tree: the modules of the build, their native files and the unit each file belongs to."""

from __future__ import annotations

import dataclasses
import os

from native_boundary_policy import Policy, Unit


NATIVE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".inc", ".S", ".s")
NATIVE_SOURCE_DIRECTORY = os.path.join("src", "main", "cpp")
# Mirrors settings.gradle.kts: a module is a directory with a build file at its group's depth.
MODULE_GROUP_DEPTHS = {"core": 1, "sdk": 1, "capability": 2, "feature": 2}


@dataclasses.dataclass(frozen=True)
class NativeFile:
    module: str
    path: str


def discover_modules(repo_root: str) -> set[str]:
    modules = {":app"} if os.path.isfile(os.path.join(repo_root, "app", "build.gradle.kts")) else set()
    for group, depth in MODULE_GROUP_DEPTHS.items():
        directories = [os.path.join(repo_root, group)]
        for _ in range(depth):
            directories = [
                os.path.join(directory, name)
                for directory in directories if os.path.isdir(directory)
                for name in sorted(os.listdir(directory))
                if os.path.isdir(os.path.join(directory, name))
            ]
        for directory in directories:
            if os.path.isfile(os.path.join(directory, "build.gradle.kts")):
                relative = os.path.relpath(directory, repo_root).replace(os.sep, "/")
                modules.add(":" + relative.replace("/", ":"))
    return modules


def module_directory(module: str) -> str:
    return module.strip(":").replace(":", "/")


def owning_unit(policy: Policy, native_path: str) -> Unit | None:
    best = None
    for unit in policy.units.values():
        if native_path == unit.path or native_path.startswith(unit.path + "/"):
            if best is None or len(unit.path) > len(best.path):
                best = unit
    return best


def collect_native_tree(repo_root: str, modules: set[str], errors: list[str]) -> dict[str, NativeFile]:
    """Every native file of every module, by its native path below the module's src/main/cpp."""
    tree: dict[str, NativeFile] = {}
    for module in sorted(modules):
        root = os.path.join(repo_root, module_directory(module), NATIVE_SOURCE_DIRECTORY)
        for directory, subdirectories, files in os.walk(root):
            subdirectories.sort()
            for name in sorted(files):
                if not name.endswith(NATIVE_SUFFIXES):
                    continue
                path = os.path.relpath(os.path.join(directory, name), repo_root).replace(os.sep, "/")
                native_path = os.path.relpath(os.path.join(directory, name), root).replace(os.sep, "/")
                if native_path in tree:
                    errors.append(f"{path} and {tree[native_path].path} both provide native path {native_path}")
                else:
                    tree[native_path] = NativeFile(module, path)
    return tree
