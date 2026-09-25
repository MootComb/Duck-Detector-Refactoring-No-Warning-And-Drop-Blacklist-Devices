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

"""Enforce native unit ownership, include direction, CMake targets and JNI owners.

Each native unit lives in the module that owns it, under <module>/src/main/cpp/<unit path>. The
src/main/cpp directories of all modules form one native tree: a file's native path is its path
below its module's src/main/cpp, no two modules may provide the same native path, and every file
belongs to exactly one unit, the one with the longest matching path, which the module holding the
file must own. A unit may include its own headers, headers of the units in its may_include list,
and the exact headers named by an include exception that states a reason. Quoted and
angle-bracket includes are both checked because each of those directories is an include directory.

The aggregate CMakeLists.txt registers every object unit, in link order, with the module that
owns it, and adds the CMakeLists.txt in the unit's directory. Object units are created by the unit
function and linked into the aggregate library, which declares no sources of its own. A unit may
instead be a standalone shared library, which may also compile the sources of units it may
include. JNI exports defined in a unit must bind JVM declarations from the unit's owning module.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
import os
import re
import sys

NATIVE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".inc", ".S", ".s")
COMPILED_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".S", ".s")
LIBRARY_KINDS = {"STATIC", "SHARED", "MODULE", "OBJECT"}
TARGET_KEYWORDS = {"PRIVATE", "PUBLIC", "INTERFACE", "EXCLUDE_FROM_ALL", "PARENT_SCOPE"}
INCLUDE_PATTERN = re.compile(r'^[ \t]*#[ \t]*include[ \t]*([<"])([^>"\n]+)[>"]', re.M)
COMMAND_PATTERN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(")
UNIT_KEYS = {"path", "owner", "target", "may_include"}
POLICY_KEYS = {
    "schema_version", "cmake_lists", "unit_registry", "unit_function", "aggregate_library",
    "units", "include_exceptions",
}
NATIVE_SOURCE_DIRECTORY = os.path.join("src", "main", "cpp")
# Mirrors settings.gradle.kts: a module is a directory with a build file at its group's depth.
MODULE_GROUP_DEPTHS = {"core": 1, "sdk": 1, "capability": 2, "feature": 2}


class PolicyError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class Unit:
    name: str
    path: str
    owner: str
    target: str
    may_include: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class Policy:
    cmake_lists: str
    unit_registry: str
    unit_function: str
    aggregate_library: str
    units: dict[str, Unit]
    exceptions: dict[tuple[str, str], str]


@dataclasses.dataclass(frozen=True)
class NativeFile:
    module: str
    path: str


@dataclasses.dataclass
class CMakeTarget:
    name: str
    kind: str
    location: str
    sources: list[str] = dataclasses.field(default_factory=list)


def load_policy(path: str) -> Policy:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or set(document) != POLICY_KEYS or document["schema_version"] != 2:
        raise PolicyError(f"{path}: expected schema_version 2 with keys {sorted(POLICY_KEYS)}")
    for key in ("cmake_lists", "unit_registry", "unit_function", "aggregate_library"):
        if not isinstance(document[key], str) or not document[key]:
            raise PolicyError(f"{key} must be a non-empty string")
    if not isinstance(document["units"], dict) or not document["units"]:
        raise PolicyError("units must be a non-empty object")
    units = {}
    for name, entry in document["units"].items():
        if not isinstance(entry, dict) or set(entry) != UNIT_KEYS:
            raise PolicyError(f"unit {name}: expected keys {sorted(UNIT_KEYS)}")
        if not all(isinstance(entry[key], str) and entry[key] for key in ("path", "owner", "target")):
            raise PolicyError(f"unit {name}: path, owner and target must be non-empty strings")
        may_include = entry["may_include"]
        if not isinstance(may_include, list) or not all(isinstance(item, str) for item in may_include):
            raise PolicyError(f"unit {name}: may_include must be a list of unit names")
        units[name] = Unit(name, entry["path"].strip("/"), entry["owner"], entry["target"], tuple(may_include))
    for unit in units.values():
        for other in unit.may_include:
            if other == unit.name or other not in units:
                raise PolicyError(f"unit {unit.name}: may_include names {other}, which is not another unit")
    for attribute in ("path", "target"):
        values = [getattr(unit, attribute) for unit in units.values()]
        shared = sorted({value for value in values if values.count(value) > 1})
        if shared:
            raise PolicyError(f"units must not share a {attribute}: {shared}")
    exceptions = {}
    if not isinstance(document["include_exceptions"], list):
        raise PolicyError("include_exceptions must be a list")
    for entry in document["include_exceptions"]:
        if not isinstance(entry, dict) or set(entry) != {"unit", "header", "reason"}:
            raise PolicyError("each include exception needs exactly unit, header and reason")
        if entry["unit"] not in units:
            raise PolicyError(f"include exception names unknown unit {entry['unit']}")
        if not isinstance(entry["reason"], str) or not entry["reason"].strip():
            raise PolicyError(f"include exception {entry['unit']} -> {entry['header']} must state a reason")
        exceptions[(entry["unit"], entry["header"])] = entry["reason"]
    return Policy(
        document["cmake_lists"], document["unit_registry"], document["unit_function"],
        document["aggregate_library"], units, exceptions,
    )


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


def strip_comments(source: str) -> str:
    """Drop comments but keep string literals and line structure, so includes keep their lines."""
    result = []
    index = 0
    length = len(source)
    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index)
            index = length if end == -1 else end
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            end = length if end == -1 else end + 2
            result.append("\n" * source.count("\n", index, end))
            index = end
        elif source[index] == '"' or (source[index] == "'" and not (index and source[index - 1].isalnum())):
            quote = source[index]
            end = index + 1
            while end < length and source[end] not in (quote, "\n"):
                end += 2 if source[end] == "\\" else 1
            result.append(source[index:end + 1])
            index = end + 1
        else:
            result.append(source[index])
            index += 1
    return "".join(result)


def resolve_include(tree: dict[str, NativeFile], including: str, delimiter: str, spelled: str) -> str | None:
    candidates = [os.path.join(os.path.dirname(including), spelled)] if delimiter == '"' else []
    candidates.append(spelled)
    for candidate in candidates:
        normalized = os.path.normpath(candidate).replace(os.sep, "/")
        if normalized.startswith("../") or normalized == ".." or os.path.isabs(normalized):
            continue
        if normalized in tree:
            return normalized
    return None


def check_includes(policy: Policy, repo_root: str, tree: dict[str, NativeFile], files: dict[str, Unit],
                   errors: list[str]) -> int:
    used_exceptions = set()
    count = 0
    for native_path, unit in sorted(files.items()):
        with open(os.path.join(repo_root, tree[native_path].path), encoding="utf-8") as handle:
            code = strip_comments(handle.read())
        for match in INCLUDE_PATTERN.finditer(code):
            delimiter, spelled = match.group(1), match.group(2).strip()
            line = code.count("\n", 0, match.start()) + 1
            location = f"{tree[native_path].path}:{line}"
            resolved = resolve_include(tree, native_path, delimiter, spelled)
            if resolved is None:
                if delimiter == '"':
                    errors.append(f"{location}: \"{spelled}\" does not resolve inside any native unit; "
                                  "include system headers with angle brackets")
                continue
            count += 1
            target = files.get(resolved)
            if target is None or target.name == unit.name or target.name in unit.may_include:
                continue
            if (unit.name, resolved) in policy.exceptions:
                used_exceptions.add((unit.name, resolved))
                continue
            errors.append(f"{location}: unit {unit.name} includes {resolved} from unit {target.name}, "
                          f"which is not in its may_include list or include exceptions")
    for unit_name, header in sorted(set(policy.exceptions) - used_exceptions):
        errors.append(f"include exception {unit_name} -> {header} is stale; no file of {unit_name} includes it")
    return count


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


def check_cmake(policy: Policy, repo_root: str, tree: dict[str, NativeFile], files: dict[str, Unit],
                errors: list[str]) -> None:
    project = CMakeProject(policy, repo_root, tree, errors)
    unit_by_target = {unit.target: unit for unit in policy.units.values()}
    registered = {}
    for unit_name, owner_directory in project.registry:
        unit = policy.units.get(unit_name)
        if unit is None:
            errors.append(f"{policy.cmake_lists}: {policy.unit_registry} registers {unit_name}, which is not a unit")
        elif module_directory(unit.owner) != owner_directory:
            errors.append(f"{policy.cmake_lists}: {policy.unit_registry} registers {unit_name} under "
                          f"{owner_directory}, but {unit.owner} owns it")
        elif unit_name in registered:
            errors.append(f"{policy.cmake_lists}: {policy.unit_registry} registers {unit_name} twice")
        registered[unit_name] = owner_directory
    for name, target in sorted(project.targets.items()):
        if name != policy.aggregate_library and name not in unit_by_target:
            errors.append(f"{target.location}: target {name} belongs to no native unit")
    for unit in policy.units.values():
        target = project.targets.get(unit.target)
        if target is None:
            errors.append(f"unit {unit.name}: CMake target {unit.target} is not declared")
            continue
        if target.kind not in ("UNIT", "SHARED", "MODULE"):
            errors.append(f"{target.location}: unit target {unit.target} must be created by "
                          f"{policy.unit_function} or be a standalone shared library")
        if target.kind == "UNIT" and unit.name not in registered:
            errors.append(f"unit {unit.name}: object unit {unit.target} is not registered in {policy.unit_registry}")
        for source in target.sources:
            owner = files.get(source)
            if owner is None:
                errors.append(f"{target.location}: {unit.target} compiles {source}, which is not a native "
                              f"file of any unit")
            elif owner.name != unit.name and not (target.kind != "UNIT" and owner.name in unit.may_include):
                errors.append(f"{target.location}: {unit.target} of unit {unit.name} compiles {source} "
                              f"owned by unit {owner.name}")
        compiled = set(target.sources)
        for native_path, owner in sorted(files.items()):
            if owner.name == unit.name and native_path.endswith(COMPILED_SUFFIXES) and native_path not in compiled:
                errors.append(f"{tree[native_path].path} is not compiled by {unit.target} of unit {unit.name}")
    aggregate = project.targets.get(policy.aggregate_library)
    if aggregate is None or aggregate.kind != "SHARED":
        errors.append(f"aggregate library {policy.aggregate_library} must be declared as a SHARED library")
    elif aggregate.sources:
        errors.append(f"aggregate library {policy.aggregate_library} must not compile sources itself: "
                      f"{aggregate.sources}")


def module_of(path: str) -> str:
    head = path.split("/src/main/", 1)[0]
    return ":" + head.replace("/", ":")


def load_jni_checker():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-jni-contracts.py")
    spec = importlib.util.spec_from_file_location("check_jni_contracts", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def check_jni_owners(repo_root: str, tree: dict[str, NativeFile], files: dict[str, Unit], errors: list[str]) -> int:
    jni = load_jni_checker()
    ignored: list[str] = []
    declarations = {}
    roots = jni.discover_source_roots(repo_root, jni.JVM_SOURCE_SET_DIRECTORIES)
    for path in jni.iter_files(roots, (".kt", ".java")):
        relative = os.path.relpath(path, repo_root).replace(os.sep, "/")
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        parse = jni.parse_kotlin if path.endswith(".kt") else jni.parse_java
        for declaration in parse(relative, source, ignored):
            declarations[declaration.expected_symbol] = declaration
    count = 0
    for native_path, unit in sorted(files.items()):
        path = tree[native_path].path
        with open(os.path.join(repo_root, path), encoding="utf-8") as handle:
            source = handle.read()
        for definition in jni.parse_native(path, source, ignored):
            declaration = declarations.get(definition.symbol)
            if declaration is None:
                continue
            count += 1
            module = module_of(declaration.path)
            if module != unit.owner:
                errors.append(f"{path}:{definition.line}: {definition.symbol} binds {declaration.class_binary_name} "
                              f"from {module}, but unit {unit.name} is owned by {unit.owner}")
    return count


def check(repo_root: str, policy: Policy, module_names: set[str]) -> tuple[list[str], str]:
    errors: list[str] = []
    for unit in policy.units.values():
        if unit.owner not in module_names:
            errors.append(f"unit {unit.name}: owner {unit.owner} is not a module of this build")
            continue
        directory = f"{module_directory(unit.owner)}/src/main/cpp/{unit.path}"
        if not os.path.isdir(os.path.join(repo_root, directory)):
            errors.append(f"unit {unit.name}: {directory} does not exist")
    tree = collect_native_tree(repo_root, module_names, errors)
    files = {}
    for native_path, native in tree.items():
        unit = owning_unit(policy, native_path)
        if unit is None:
            errors.append(f"{native.path} belongs to no native unit")
        elif unit.owner != native.module:
            errors.append(f"{native.path} belongs to unit {unit.name}, which {unit.owner} owns, "
                          f"but lives in {native.module}")
        else:
            files[native_path] = unit
    includes = check_includes(policy, repo_root, tree, files, errors)
    check_cmake(policy, repo_root, tree, files, errors)
    exports = check_jni_owners(repo_root, tree, files, errors)
    owners = {unit.owner for unit in policy.units.values()}
    summary = (f"Native boundaries verified: {len(policy.units)} units in {len(owners)} modules, {len(files)} "
               f"files, {includes} project includes, {exports} JNI exports.")
    return errors, summary


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    parser.add_argument("--repo-root", default=default_root)
    parser.add_argument("--policy", default=None, help="defaults to .github/policies/native-boundaries.json")
    arguments = parser.parse_args(argv)
    repo_root = os.path.abspath(arguments.repo_root)
    policies = os.path.join(repo_root, ".github", "policies")
    try:
        policy = load_policy(arguments.policy or os.path.join(policies, "native-boundaries.json"))
        module_names = discover_modules(repo_root)
    except (OSError, PolicyError, json.JSONDecodeError) as error:
        print(f"native boundary policy error: {error}", file=sys.stderr)
        return 2
    errors, summary = check(repo_root, policy, module_names)
    if errors:
        for error in errors:
            print(f"native boundary violation: {error}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
