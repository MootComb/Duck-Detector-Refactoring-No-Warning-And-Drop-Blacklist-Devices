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

"""Verify that every JNI declaration binds to exactly one exported native definition.

DuckDetector binds native methods through the static JNI naming scheme described in the
JNI specification ("Resolving Native Method Names"), never through RegisterNatives. The
expected symbol is therefore a pure function of the declaring class's binary name and the
method's JVM name. Moving a bridge to another package or module changes that symbol; the
mismatch only surfaces at runtime as UnsatisfiedLinkError, which some bridges report as
"nothing observed". This check turns that drift into a build failure.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import re
import sys
from typing import Iterable, Iterator

SKIPPED_DIRECTORIES = {".git", ".gradle", ".idea", ".kotlin", ".cxx", "build", "node_modules"}
JVM_SOURCE_SET_DIRECTORIES = {"java", "kotlin"}
NATIVE_SOURCE_SET_DIRECTORIES = {"cpp"}
NATIVE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp")
# Lines that continue a declaration header, such as the ") : Base {" that closes a
# multi-line constructor, sit at the type's own indentation without closing it.
CONTINUATION_PREFIXES = (")", "]")

PACKAGE_PATTERN = re.compile(r"^\s*package\s+([A-Za-z_][\w.]*)")
KOTLIN_TYPE_PATTERN = re.compile(
    r"^(?P<indent>[ \t]*)(?:@[\w.]+(?:\([^)]*\))?\s+)*"
    r"(?:(?:public|internal|private|protected|open|abstract|sealed|data|final|inner|enum|"
    r"annotation|value|inline|expect|actual|fun)\s+)*"
    r"(?P<kind>companion\s+object|class|object|interface)\b(?:\s+(?P<name>[A-Za-z_]\w*))?"
)
KOTLIN_EXTERNAL_PATTERN = re.compile(
    r"^(?P<indent>[ \t]*)(?P<modifiers>(?:(?:@[\w.]+(?:\([^)]*\))?|public|internal|private|"
    r"protected|external|override|open|final|actual|inline|suspend)\s+)*)fun\s+"
    r"(?:<[^>]*>\s*)?(?P<name>[A-Za-z_]\w*)\s*\("
)
KOTLIN_ANNOTATION_ONLY_PATTERN = re.compile(r"^[ \t]*(?:@[\w.]+(?:\([^)]*\))?\s*)+$")
JVM_NAME_PATTERN = re.compile(r"@(?:kotlin\.jvm\.)?JvmName\(\s*\"([^\"]+)\"\s*\)")
JAVA_TYPE_PATTERN = re.compile(
    r"^(?P<indent>[ \t]*)(?:(?:public|private|protected|static|final|abstract|sealed|non-sealed)\s+)*"
    r"(?P<kind>class|interface|enum|record)\s+(?P<name>[A-Za-z_]\w*)"
)
JAVA_NATIVE_PATTERN = re.compile(
    r"^(?P<indent>[ \t]*)(?:(?:public|private|protected|static|final|synchronized)\s+)*native\s+"
    r"[\w<>\[\],.? ]+?\s+(?P<name>[A-Za-z_]\w*)\s*\("
)
NATIVE_SYMBOL_PATTERN = re.compile(r"\bJava_[A-Za-z0-9_]+")


@dataclasses.dataclass(frozen=True)
class JvmDeclaration:
    path: str
    line: int
    class_binary_name: str
    method_name: str

    @property
    def expected_symbol(self) -> str:
        return f"Java_{mangle(self.class_binary_name)}_{mangle(self.method_name)}"


@dataclasses.dataclass(frozen=True)
class NativeDefinition:
    path: str
    line: int
    symbol: str


def mangle(name: str) -> str:
    """Escape a class binary name or method name per the JNI short-name rules."""
    escaped = []
    for character in name:
        if character in "./":
            escaped.append("_")
        elif character == "_":
            escaped.append("_1")
        elif character == ";":
            escaped.append("_2")
        elif character == "[":
            escaped.append("_3")
        elif character.isascii() and character.isalnum():
            escaped.append(character)
        else:
            escaped.append(f"_0{ord(character):04x}")
    return "".join(escaped)


def discover_source_roots(repo_root: str, leaf_names: set[str]) -> list[str]:
    roots = []
    for directory, subdirectories, _ in os.walk(repo_root):
        subdirectories[:] = sorted(name for name in subdirectories if name not in SKIPPED_DIRECTORIES)
        parts = os.path.relpath(directory, repo_root).split(os.sep)
        if len(parts) >= 3 and parts[-3] == "src" and parts[-2] == "main" and parts[-1] in leaf_names:
            roots.append(directory)
            subdirectories[:] = []
    return roots


def iter_files(roots: Iterable[str], suffixes: tuple[str, ...]) -> Iterator[str]:
    for root in roots:
        for directory, subdirectories, files in os.walk(root):
            subdirectories[:] = sorted(name for name in subdirectories if name not in SKIPPED_DIRECTORIES)
            for name in sorted(files):
                if name.endswith(suffixes):
                    yield os.path.join(directory, name)


def indentation_width(indent: str) -> int:
    return len(indent.expandtabs(4))


class TypeScope:
    """Tracks enclosing type declarations by indentation, which the project formatter keeps consistent."""

    def __init__(self) -> None:
        self._stack: list[tuple[int, str, bool]] = []

    def close_until(self, width: int) -> None:
        while self._stack and self._stack[-1][0] >= width:
            self._stack.pop()

    def open(self, width: int, name: str, is_companion: bool) -> None:
        self.close_until(width)
        self._stack.append((width, name, is_companion))

    def chain(self) -> list[tuple[str, bool]]:
        return [(name, is_companion) for _, name, is_companion in self._stack]


def parse_kotlin(path: str, source: str, errors: list[str]) -> list[JvmDeclaration]:
    package = ""
    declarations = []
    seen_names: dict[str, int] = {}
    scope = TypeScope()
    pending_annotations: list[str] = []
    in_raw_string = False
    for number, line in enumerate(source.splitlines(), start=1):
        if line.count('"""') % 2 == 1:
            in_raw_string = not in_raw_string
            continue
        if in_raw_string:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "*", "/*")):
            continue
        package_match = PACKAGE_PATTERN.match(line)
        if package_match:
            package = package_match.group(1)
            continue
        if KOTLIN_ANNOTATION_ONLY_PATTERN.match(line):
            pending_annotations.append(stripped)
            continue
        annotations = " ".join(pending_annotations)
        pending_annotations = []
        width = indentation_width(line[: len(line) - len(line.lstrip())])
        external_match = KOTLIN_EXTERNAL_PATTERN.match(line)
        if external_match and re.search(r"\bexternal\b", external_match.group("modifiers")):
            scope.close_until(width)
            location = f"{path}:{number}"
            chain = scope.chain()
            modifiers = f"{annotations} {external_match.group('modifiers')}"
            if not chain:
                errors.append(f"{location}: top-level external functions are not bound by this project")
                continue
            if any(is_companion for _, is_companion in chain):
                errors.append(
                    f"{location}: external functions in companion objects are unsupported; "
                    "declare them in a top-level class or object"
                )
                continue
            if re.search(r"\binternal\b", modifiers):
                errors.append(
                    f"{location}: internal external functions get a module-dependent JVM name; "
                    "use private or public visibility"
                )
                continue
            jvm_name_match = JVM_NAME_PATTERN.search(modifiers)
            method_name = jvm_name_match.group(1) if jvm_name_match else external_match.group("name")
            class_binary_name = ".".join(filter(None, [package, "$".join(name for name, _ in chain)]))
            key = f"{class_binary_name}#{method_name}"
            if key in seen_names:
                errors.append(
                    f"{location}: overloaded native method {method_name} requires long-form JNI names, "
                    "which this project does not use"
                )
                continue
            seen_names[key] = number
            declarations.append(JvmDeclaration(path, number, class_binary_name, method_name))
            continue
        type_match = KOTLIN_TYPE_PATTERN.match(line)
        if type_match:
            kind = type_match.group("kind")
            is_companion = kind.startswith("companion")
            name = type_match.group("name") or ("Companion" if is_companion else None)
            if name:
                scope.open(width, name, is_companion)
                continue
        if not stripped.startswith(CONTINUATION_PREFIXES):
            scope.close_until(width)
    return declarations


def parse_java(path: str, source: str, errors: list[str]) -> list[JvmDeclaration]:
    package = ""
    declarations = []
    seen_names: set[str] = set()
    scope = TypeScope()
    for number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "*", "/*")):
            continue
        package_match = PACKAGE_PATTERN.match(line)
        if package_match:
            package = package_match.group(1).rstrip(";")
            continue
        width = indentation_width(line[: len(line) - len(line.lstrip())])
        native_match = JAVA_NATIVE_PATTERN.match(line)
        if native_match:
            scope.close_until(width)
            chain = scope.chain()
            location = f"{path}:{number}"
            if not chain:
                errors.append(f"{location}: native method outside a type declaration")
                continue
            class_binary_name = ".".join(filter(None, [package, "$".join(name for name, _ in chain)]))
            key = f"{class_binary_name}#{native_match.group('name')}"
            if key in seen_names:
                errors.append(f"{location}: overloaded native method requires long-form JNI names")
                continue
            seen_names.add(key)
            declarations.append(JvmDeclaration(path, number, class_binary_name, native_match.group("name")))
            continue
        type_match = JAVA_TYPE_PATTERN.match(line)
        if type_match:
            scope.open(width, type_match.group("name"), False)
            continue
        if not stripped.startswith(CONTINUATION_PREFIXES):
            scope.close_until(width)
    return declarations


def blank_comments_and_literals(source: str) -> str:
    """Replace comments and string/char literals with spaces, preserving offsets and newlines."""
    result = list(source)
    index = 0
    length = len(source)

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if result[position] != "\n":
                result[position] = " "

    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = length if end == -1 else end
            blank(index, end)
            index = end
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            end = length if end == -1 else end + 2
            blank(index, end)
            index = end
        elif source[index] in "\"'":
            quote = source[index]
            end = index + 1
            while end < length and source[end] != quote and source[end] != "\n":
                end += 2 if source[end] == "\\" else 1
            is_linkage_literal = (
                quote == '"'
                and source[index + 1 : end] == "C"
                and re.search(r"\bextern\s*$", source[max(0, index - 32) : index]) is not None
            )
            if not is_linkage_literal:
                blank(index + 1, min(end, length))
            index = end + 1
        else:
            index += 1
    return "".join(result)


def extern_c_block_ranges(code: str) -> list[tuple[int, int]]:
    ranges = []
    for match in re.finditer(r'extern\s+"C"\s*\{', code):
        depth = 0
        for position in range(match.end() - 1, len(code)):
            if code[position] == "{":
                depth += 1
            elif code[position] == "}":
                depth -= 1
                if depth == 0:
                    ranges.append((match.end(), position))
                    break
    return ranges


def declaration_prefix(code: str, start: int) -> str:
    boundary = max(code.rfind(";", 0, start), code.rfind("}", 0, start), code.rfind("{", 0, start))
    prefix = code[boundary + 1 : start]
    return re.sub(r"^\s*#.*$", "", prefix, flags=re.M)


def parse_native(path: str, source: str, errors: list[str]) -> list[NativeDefinition]:
    code = blank_comments_and_literals(source)
    if re.search(r"\bRegisterNatives\b", code):
        errors.append(f"{path}: RegisterNatives is not covered by this check; extend it before relying on dynamic registration")
    extern_blocks = extern_c_block_ranges(code)
    definitions = []
    for match in NATIVE_SYMBOL_PATTERN.finditer(code):
        position = match.end()
        while position < len(code) and code[position].isspace():
            position += 1
        if position >= len(code) or code[position] != "(":
            continue
        depth = 0
        while position < len(code):
            if code[position] == "(":
                depth += 1
            elif code[position] == ")":
                depth -= 1
                if depth == 0:
                    break
            position += 1
        position += 1
        while position < len(code) and code[position].isspace():
            position += 1
        if position >= len(code) or code[position] != "{":
            continue
        line = code.count("\n", 0, match.start()) + 1
        location = f"{path}:{line}"
        prefix = declaration_prefix(code, match.start())
        in_extern_block = any(start <= match.start() <= end for start, end in extern_blocks)
        if not in_extern_block and not re.search(r'extern\s+"C"', prefix):
            errors.append(f"{location}: {match.group(0)} lacks C linkage, so the JVM cannot resolve it")
        if not re.search(r"\bJNIEXPORT\b", prefix):
            errors.append(f"{location}: {match.group(0)} lacks JNIEXPORT and is hidden under -fvisibility=hidden")
        definitions.append(NativeDefinition(path, line, match.group(0)))
    return definitions


def check(repo_root: str) -> tuple[list[str], int]:
    errors: list[str] = []
    jvm_roots = discover_source_roots(repo_root, JVM_SOURCE_SET_DIRECTORIES)
    native_roots = discover_source_roots(repo_root, NATIVE_SOURCE_SET_DIRECTORIES)
    declarations: list[JvmDeclaration] = []
    for path in iter_files(jvm_roots, (".kt", ".java")):
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        relative = os.path.relpath(path, repo_root)
        if path.endswith(".kt"):
            declarations.extend(parse_kotlin(relative, source, errors))
        else:
            declarations.extend(parse_java(relative, source, errors))
    definitions: dict[str, list[NativeDefinition]] = {}
    for path in iter_files(native_roots, NATIVE_SUFFIXES):
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        for definition in parse_native(os.path.relpath(path, repo_root), source, errors):
            definitions.setdefault(definition.symbol, []).append(definition)
    for symbol, sites in sorted(definitions.items()):
        if len(sites) > 1:
            where = ", ".join(f"{site.path}:{site.line}" for site in sites)
            errors.append(f"{symbol} is defined {len(sites)} times ({where})")
    expected = {}
    for declaration in declarations:
        expected[declaration.expected_symbol] = declaration
        if declaration.expected_symbol not in definitions:
            errors.append(
                f"{declaration.path}:{declaration.line}: {declaration.class_binary_name}."
                f"{declaration.method_name} has no native definition named {declaration.expected_symbol}"
            )
    for symbol, sites in sorted(definitions.items()):
        if symbol not in expected:
            site = sites[0]
            errors.append(f"{site.path}:{site.line}: {symbol} has no matching JVM native declaration")
    return errors, len(declarations)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--repo-root",
        default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
        help="repository root to scan (defaults to the checkout containing this script)",
    )
    arguments = parser.parse_args(argv)
    repo_root = os.path.abspath(arguments.repo_root)
    if not os.path.isdir(repo_root):
        print(f"repository root does not exist: {repo_root}", file=sys.stderr)
        return 2
    errors, binding_count = check(repo_root)
    if errors:
        for error in errors:
            print(f"jni contract violation: {error}", file=sys.stderr)
        return 1
    if binding_count == 0:
        print("jni contract violation: no JNI declarations were found; the scan roots are wrong", file=sys.stderr)
        return 1
    print(f"JNI contracts verified: {binding_count} bindings.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
