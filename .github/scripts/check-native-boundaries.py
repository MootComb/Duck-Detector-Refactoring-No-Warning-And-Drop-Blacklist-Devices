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
import importlib.util
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from native_boundary_policy import Policy, PolicyError, Unit, load_policy  # noqa: E402
from native_cmake import COMPILED_SUFFIXES, CMakeProject  # noqa: E402
from native_tree import (  # noqa: E402
    NativeFile, collect_native_tree, discover_modules, module_directory, owning_unit,
)

INCLUDE_PATTERN = re.compile(r'^[ \t]*#[ \t]*include[ \t]*([<"])([^>"\n]+)[>"]', re.M)


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
