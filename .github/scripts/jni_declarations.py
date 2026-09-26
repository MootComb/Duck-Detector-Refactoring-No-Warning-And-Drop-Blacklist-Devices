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

"""JVM native method declarations in Kotlin and Java sources, and the JNI symbols they expect."""

from __future__ import annotations

import dataclasses
import re


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


@dataclasses.dataclass(frozen=True)
class JvmDeclaration:
    path: str
    line: int
    class_binary_name: str
    method_name: str

    @property
    def expected_symbol(self) -> str:
        return f"Java_{mangle(self.class_binary_name)}_{mangle(self.method_name)}"


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
