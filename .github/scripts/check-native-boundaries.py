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

Every file under the native source root belongs to exactly one unit, the one with the longest
matching path. A unit may include its own headers, headers of the units in its may_include
list, and the exact headers named by an include exception that states a reason. Quoted and
angle-bracket includes are both checked because the source root is also an include directory.

Each unit compiles through its own CMake target. Object units are created by the unit function
and linked into the aggregate library, which declares no sources of its own. A unit may instead
be a standalone shared library, which may also compile the sources of units it may include.
JNI exports defined in a unit must bind JVM declarations from the unit's owning module.
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
TARGET_KEYWORDS = {"PRIVATE", "PUBLIC", "INTERFACE", "EXCLUDE_FROM_ALL"}
INCLUDE_PATTERN = re.compile(r'^[ \t]*#[ \t]*include[ \t]*([<"])([^>"\n]+)[>"]', re.M)
COMMAND_PATTERN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(")
UNIT_KEYS = {"path", "owner", "target", "may_include"}
POLICY_KEYS = {
    "schema_version", "source_root", "cmake_lists", "unit_function", "aggregate_library",
    "units", "include_exceptions",
}


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
    source_root: str
    cmake_lists: str
    unit_function: str
    aggregate_library: str
    units: dict[str, Unit]
    exceptions: dict[tuple[str, str], str]


@dataclasses.dataclass
class CMakeTarget:
    name: str
    kind: str
    line: int
    sources: list[str] = dataclasses.field(default_factory=list)
    links: list[str] = dataclasses.field(default_factory=list)


def load_policy(path: str) -> Policy:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or set(document) != POLICY_KEYS or document["schema_version"] != 1:
        raise PolicyError(f"{path}: expected schema_version 1 with keys {sorted(POLICY_KEYS)}")
    for key in ("source_root", "cmake_lists", "unit_function", "aggregate_library"):
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
        document["source_root"].strip("/"), document["cmake_lists"], document["unit_function"],
        document["aggregate_library"], units, exceptions,
    )


def load_module_names(path: str) -> set[str]:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    members = document.get("members") if isinstance(document, dict) else None
    if not isinstance(members, dict):
        raise PolicyError(f"{path}: module policy has no members object")
    return set(members)


def owning_unit(policy: Policy, relative: str) -> Unit | None:
    best = None
    for unit in policy.units.values():
        if relative == unit.path or relative.startswith(unit.path + "/"):
            if best is None or len(unit.path) > len(best.path):
                best = unit
    return best


def iter_native_files(source_root: str):
    for directory, subdirectories, files in os.walk(source_root):
        subdirectories.sort()
        for name in sorted(files):
            if name.endswith(NATIVE_SUFFIXES):
                path = os.path.join(directory, name)
                yield os.path.relpath(path, source_root).replace(os.sep, "/"), path


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


def resolve_include(source_root: str, including: str, delimiter: str, spelled: str) -> str | None:
    candidates = [os.path.join(os.path.dirname(including), spelled)] if delimiter == '"' else []
    candidates.append(spelled)
    for candidate in candidates:
        normalized = os.path.normpath(candidate).replace(os.sep, "/")
        if normalized.startswith("../") or normalized == ".." or os.path.isabs(normalized):
            continue
        if os.path.isfile(os.path.join(source_root, normalized)):
            return normalized
    return None


def check_includes(policy: Policy, source_root: str, files: dict[str, Unit], errors: list[str]) -> int:
    used_exceptions = set()
    count = 0
    for relative, unit in sorted(files.items()):
        with open(os.path.join(source_root, relative), encoding="utf-8") as handle:
            code = strip_comments(handle.read())
        for match in INCLUDE_PATTERN.finditer(code):
            delimiter, spelled = match.group(1), match.group(2).strip()
            line = code.count("\n", 0, match.start()) + 1
            location = f"{policy.source_root}/{relative}:{line}"
            resolved = resolve_include(source_root, relative, delimiter, spelled)
            if resolved is None:
                if delimiter == '"':
                    errors.append(f"{location}: \"{spelled}\" does not resolve inside {policy.source_root}; "
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


def parse_cmake(path: str, unit_function: str, errors: list[str]) -> dict[str, CMakeTarget]:
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    variables: dict[str, list[str]] = {}
    targets: dict[str, CMakeTarget] = {}

    def expand(arguments: list[str]) -> list[str]:
        values = []
        for argument in arguments:
            reference = re.fullmatch(r"\$\{(\w+)\}", argument)
            if reference and reference.group(1) in variables:
                values.extend(variables[reference.group(1)])
            else:
                values.append(argument.replace("${CMAKE_CURRENT_SOURCE_DIR}/", ""))
        return values

    def declare(name: str, kind: str, line: int, sources: list[str]) -> None:
        if name in targets:
            errors.append(f"{path}:{line}: target {name} is declared twice")
            return
        targets[name] = CMakeTarget(name, kind, line, [source for source in sources if source not in TARGET_KEYWORDS])

    for command, arguments, line in cmake_commands(text):
        if not arguments:
            continue
        name, rest = arguments[0], expand(arguments[1:])
        if command == "set":
            variables[name] = rest
        elif command == unit_function.lower():
            declare(name, "UNIT", line, rest)
        elif command == "add_library":
            kind = rest[0] if rest and rest[0] in LIBRARY_KINDS else "STATIC"
            declare(name, kind, line, rest[1:] if rest and rest[0] in LIBRARY_KINDS else rest)
        elif command in ("target_sources", "target_link_libraries"):
            if name not in targets:
                errors.append(f"{path}:{line}: {command} names undeclared target {name}")
                continue
            values = [value for value in rest if value not in TARGET_KEYWORDS]
            (targets[name].sources if command == "target_sources" else targets[name].links).extend(values)
    return targets


def check_cmake(policy: Policy, repo_root: str, files: dict[str, Unit], errors: list[str]) -> None:
    cmake_path = os.path.join(repo_root, policy.cmake_lists)
    targets = parse_cmake(cmake_path, policy.unit_function, errors)
    source_root = os.path.join(repo_root, policy.source_root)
    for target in targets.values():
        target.sources = [
            os.path.relpath(os.path.join(os.path.dirname(cmake_path), source), source_root).replace(os.sep, "/")
            for source in target.sources
        ]
    unit_by_target = {unit.target: unit for unit in policy.units.values()}
    for name, target in sorted(targets.items()):
        if name != policy.aggregate_library and name not in unit_by_target:
            errors.append(f"{policy.cmake_lists}:{target.line}: target {name} belongs to no native unit")
    for unit in policy.units.values():
        target = targets.get(unit.target)
        if target is None:
            errors.append(f"unit {unit.name}: CMake target {unit.target} is not declared")
            continue
        if target.kind not in ("UNIT", "SHARED", "MODULE"):
            errors.append(f"{policy.cmake_lists}:{target.line}: unit target {unit.target} must be created by "
                          f"{policy.unit_function} or be a standalone shared library")
        for source in target.sources:
            owner = files.get(source)
            if owner is None:
                errors.append(f"{policy.cmake_lists}: {unit.target} compiles {source}, which is not a native "
                              f"file of any unit")
            elif owner.name != unit.name and not (target.kind != "UNIT" and owner.name in unit.may_include):
                errors.append(f"{policy.cmake_lists}: {unit.target} of unit {unit.name} compiles {source} "
                              f"owned by unit {owner.name}")
        compiled = set(target.sources)
        for relative, owner in sorted(files.items()):
            if owner.name == unit.name and relative.endswith(COMPILED_SUFFIXES) and relative not in compiled:
                errors.append(f"{policy.source_root}/{relative} is not compiled by {unit.target} of unit {unit.name}")
    aggregate = targets.get(policy.aggregate_library)
    if aggregate is None or aggregate.kind != "SHARED":
        errors.append(f"aggregate library {policy.aggregate_library} must be declared as a SHARED library")
        return
    if aggregate.sources:
        errors.append(f"aggregate library {policy.aggregate_library} must not compile sources itself: "
                      f"{aggregate.sources}")
    for name, target in sorted(targets.items()):
        if target.kind == "UNIT" and name not in aggregate.links:
            errors.append(f"aggregate library {policy.aggregate_library} does not link unit target {name}")


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


def check_jni_owners(policy: Policy, repo_root: str, files: dict[str, Unit], errors: list[str]) -> int:
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
    for relative, unit in sorted(files.items()):
        path = f"{policy.source_root}/{relative}"
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
            errors.append(f"unit {unit.name}: owner {unit.owner} is not a module in the module boundary policy")
    source_root = os.path.join(repo_root, policy.source_root)
    for unit in policy.units.values():
        if not os.path.isdir(os.path.join(source_root, unit.path)):
            errors.append(f"unit {unit.name}: {policy.source_root}/{unit.path} does not exist")
    files = {}
    for relative, _ in iter_native_files(source_root):
        unit = owning_unit(policy, relative)
        if unit is None:
            errors.append(f"{policy.source_root}/{relative} belongs to no native unit")
        else:
            files[relative] = unit
    includes = check_includes(policy, source_root, files, errors)
    check_cmake(policy, repo_root, files, errors)
    exports = check_jni_owners(policy, repo_root, files, errors)
    summary = (f"Native boundaries verified: {len(policy.units)} units, {len(files)} files, "
               f"{includes} project includes, {exports} JNI exports.")
    return errors, summary


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    parser.add_argument("--repo-root", default=default_root)
    parser.add_argument("--policy", default=None, help="defaults to .github/policies/native-boundaries.json")
    parser.add_argument("--module-policy", default=None, help="defaults to .github/policies/module-boundaries.json")
    arguments = parser.parse_args(argv)
    repo_root = os.path.abspath(arguments.repo_root)
    policies = os.path.join(repo_root, ".github", "policies")
    try:
        policy = load_policy(arguments.policy or os.path.join(policies, "native-boundaries.json"))
        module_names = load_module_names(arguments.module_policy or os.path.join(policies, "module-boundaries.json"))
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
