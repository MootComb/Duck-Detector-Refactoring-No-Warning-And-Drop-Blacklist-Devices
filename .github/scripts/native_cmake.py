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

"""A model of the native CMake project: the targets it declares and the native files they compile."""

from __future__ import annotations

import dataclasses
import os
import re

from native_boundary_policy import Policy
from native_tree import NATIVE_SOURCE_DIRECTORY, NativeFile


COMPILED_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".S", ".s")
LIBRARY_KINDS = {"STATIC", "SHARED", "MODULE", "OBJECT"}
TARGET_KEYWORDS = {"PRIVATE", "PUBLIC", "INTERFACE", "EXCLUDE_FROM_ALL", "PARENT_SCOPE"}
COMMAND_PATTERN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(")


@dataclasses.dataclass
class CMakeTarget:
    name: str
    kind: str
    location: str
    sources: list[str] = dataclasses.field(default_factory=list)


def cmake_commands(text: str):
    """Yield (command, arguments, line) for top-level CMake commands outside function bodies."""
    code = re.sub(r'"(?:[^"\\]|\\.)*"|#[^\n]*', lambda match: match.group(0) if match.group(0)[0] == '"' else "", text)
    position = 0
    function_depth = 0
    while True:
        match = COMMAND_PATTERN.search(code, position)
        if match is None:
            return
        index, depth = match.end() - 1, 0
        while index < len(code):
            if code[index] == '"':
                index = code.index('"', index + 1)
            elif code[index] == "(":
                depth += 1
            elif code[index] == ")":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        command = match.group(1).lower()
        arguments = [token.strip('"') for token in re.findall(r'"[^"]*"|[^\s]+', code[match.end():index])]
        line = code.count("\n", 0, match.start()) + 1
        position = index + 1
        if command in ("function", "macro"):
            function_depth += 1
        elif command in ("endfunction", "endmacro"):
            function_depth -= 1
        elif function_depth == 0:
            yield command, arguments, line


class CMakeProject:
    """The aggregate CMakeLists.txt and every unit CMakeLists.txt it adds, read in build order."""

    def __init__(self, policy: Policy, repo_root: str, tree: dict[str, NativeFile], errors: list[str]):
        self.policy = policy
        self.repo_root = repo_root
        self.errors = errors
        self.by_real_path = {
            os.path.normpath(os.path.join(repo_root, native.path)): native_path for native_path, native in tree.items()
        }
        self.variables: dict[str, list[str]] = {}
        self.targets: dict[str, CMakeTarget] = {}
        self.registry: list[tuple[str, str]] = []
        self.aggregate_path = os.path.join(repo_root, policy.cmake_lists)
        self.read(self.aggregate_path)
        values = self.variables.get(policy.unit_registry, [])
        if not values or len(values) % 2:
            errors.append(f"{policy.cmake_lists}: {policy.unit_registry} must list unit and owner pairs")
        self.registry = list(zip(values[0::2], values[1::2]))
        for unit_name, owner_directory in self.registry:
            self.read(os.path.join(repo_root, owner_directory, NATIVE_SOURCE_DIRECTORY, unit_name, "CMakeLists.txt"))

    def display(self, path: str) -> str:
        return os.path.relpath(path, self.repo_root).replace(os.sep, "/")

    def read(self, path: str) -> None:
        if not os.path.isfile(path):
            self.errors.append(f"{self.display(path)} does not exist")
            return
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        directory = os.path.dirname(path)
        for command, arguments, line in cmake_commands(text):
            if not arguments:
                continue
            location = f"{self.display(path)}:{line}"
            name, rest = arguments[0], self.expand(arguments[1:], directory)
            if command == "set":
                self.variables[name] = [value for value in rest if value not in TARGET_KEYWORDS]
            elif command == self.policy.unit_function.lower():
                self.declare(name, "UNIT", location, self.native_paths(rest, directory))
            elif command == "add_library":
                kind = rest[0] if rest and rest[0] in LIBRARY_KINDS else "STATIC"
                sources = rest[1:] if rest and rest[0] in LIBRARY_KINDS else rest
                self.declare(name, kind, location, self.native_paths(sources, directory))
            elif command == "target_sources":
                if name not in self.targets:
                    self.errors.append(f"{location}: target_sources names undeclared target {name}")
                    continue
                self.targets[name].sources += self.native_paths(rest, directory)
            elif command == "add_subdirectory" and path != self.aggregate_path:
                self.read(os.path.join(directory, name, "CMakeLists.txt"))

    def expand(self, arguments: list[str], directory: str) -> list[str]:
        values = []
        for argument in arguments:
            reference = re.fullmatch(r"\$\{(\w+)\}", argument)
            if reference and reference.group(1) in self.variables:
                values.extend(self.variables[reference.group(1)])
            else:
                values.append(argument.replace("${CMAKE_CURRENT_SOURCE_DIR}", directory))
        return values

    def native_paths(self, values: list[str], directory: str) -> list[str]:
        """Native paths of the compiled sources in [values]; CMake resolves relative ones against [directory]."""
        sources = []
        for value in values:
            if value in TARGET_KEYWORDS or not value.endswith(COMPILED_SUFFIXES):
                continue
            real = os.path.normpath(value if os.path.isabs(value) else os.path.join(directory, value))
            sources.append(self.by_real_path.get(real, "<outside the native tree>/" + self.display(real)))
        return sources

    def declare(self, name: str, kind: str, location: str, sources: list[str]) -> None:
        if name in self.targets:
            self.errors.append(f"{location}: target {name} is declared twice")
            return
        self.targets[name] = CMakeTarget(name, kind, location, sources)
