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

"""Exported JNI function definitions in C and C++ sources."""

from __future__ import annotations

import dataclasses
import re


NATIVE_SYMBOL_PATTERN = re.compile(r"\bJava_[A-Za-z0-9_]+")


@dataclasses.dataclass(frozen=True)
class NativeDefinition:
    path: str
    line: int
    symbol: str


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
