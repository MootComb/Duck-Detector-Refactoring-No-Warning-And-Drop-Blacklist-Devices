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

"""Fail when presentation, ui, SDK or native code branches on text another layer or unit wrote.

A layer that recovers meaning from display text breaks silently when that text is reworded: a card
that searches a summary for "key visibility" or a native unit that compares another unit's finding
labels. Such decisions must come from typed values. In the Kotlin roots this rejects comparing or
searching strings against literals (==, when branches, contains, startsWith, removePrefix and the
like, membership in a literal set) and comparing a display field such as a label or title with a
variable. In the native roots it rejects comparing or searching a finding's label, group, title or
similar field against text. Code that interprets text by nature, such as a wire codec or a platform
value, is listed with a reason; an entry the file no longer needs is rejected. Comments and string
contents are ignored, and tests are not scanned.
"""

from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import os
import re
import sys

KOTLIN_SUFFIXES = (".kt",)
NATIVE_SUFFIXES = (".c", ".cc", ".cpp", ".h", ".hpp")
SKIPPED_DIRECTORIES = {".git", ".gradle", ".idea", ".kotlin", ".cxx", "build", "node_modules", "__pycache__"}
DISPLAY_FIELDS = r"(?:label|title|summary|detail|details|body|text|message|headline|description)"
FINDING_FIELDS = r"(?:label|group|title|detail|message|method|summary|category|section|kind|status)"
KOTLIN_PATTERNS = [
    (r"[!=]==?\s*\"|\"\s*[!=]==?", "compares with a string literal"),
    (r"(?m)^\s*\"[^\"\n]*\"(?:\s*,\s*\"[^\"\n]*\")*\s*->", "branches on a string literal"),
    (r"\.(?:contains|startsWith|endsWith|equals|matches|removePrefix|removeSuffix|removeSurrounding|"
     r"substringBefore|substringAfter|substringBeforeLast|substringAfterLast|indexOf|lastIndexOf)\(\s*\"",
     "searches text for a literal"),
    (r"\bin\s+(?:setOf|listOf|arrayOf|hashSetOf|mutableSetOf)\(\s*\"", "looks text up in a literal set"),
    (r"\." + DISPLAY_FIELDS + r"\s*[!=]=\s*[a-z_]|\." + DISPLAY_FIELDS + r"\s*\.\s*equals\(",
     "compares a display field"),
]
NATIVE_PATTERNS = [
    (r"(?:\.|->)" + FINDING_FIELDS + r"\s*[!=]=\s*\"|\"\s*[!=]=\s*[\w\].>-]*(?:\.|->)" + FINDING_FIELDS + r"\b",
     "compares a finding field with a string literal"),
    (r"\bstrn?cmp\s*\([^;]*(?:\.|->)" + FINDING_FIELDS + r"\b", "compares a finding field with strcmp"),
    (r"(?:\.|->)" + FINDING_FIELDS + r"\s*\.\s*(?:find|rfind|starts_with|ends_with|compare|contains)\s*\(",
     "searches a finding field"),
]
KOTLIN_COMPILED = [(re.compile(pattern), label) for pattern, label in KOTLIN_PATTERNS]
NATIVE_COMPILED = [(re.compile(pattern), label) for pattern, label in NATIVE_PATTERNS]


def _load_literal_blanker():
    # Kotlin literals and comments are blanked by the reflection checker's scanner, so the two checkers
    # agree on what is code.
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-reflection-boundaries.py")
    spec = importlib.util.spec_from_file_location("reflection_boundaries", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.blank_literals


blank_kotlin = _load_literal_blanker()


class PolicyError(ValueError):
    pass


def blank_native(source: str) -> str:
    """Blank C and C++ comments and literal text, keeping quotes and line structure."""
    out = list(source)
    length = len(source)
    index = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, min(end, length)):
            if out[position] != "\n":
                out[position] = " "

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
        elif source.startswith('R"', index) and (index == 0 or not (source[index - 1].isalnum() or source[index - 1] == "_")):
            open_paren = source.find("(", index + 2)
            delimiter = source[index + 2:open_paren]
            close = source.find(")" + delimiter + '"', open_paren)
            close = length if close == -1 else close
            blank(open_paren + 1, close)
            index = close + len(delimiter) + 2
        elif source[index] in "\"'":
            quote = source[index]
            end = index + 1
            while end < length and source[end] != quote and source[end] != "\n":
                end += 2 if source[end] == "\\" else 1
            blank(index + 1, end)
            index = end + 1
        else:
            index += 1
    return "".join(out)


def find_uses(source: str, native: bool) -> list[tuple[int, str]]:
    code = blank_native(source) if native else blank_kotlin(source)
    uses: list[tuple[int, str]] = []
    for pattern, label in NATIVE_COMPILED if native else KOTLIN_COMPILED:
        for match in pattern.finditer(code):
            uses.append((code.count("\n", 0, match.start()) + 1, label))
    return sorted(set(uses))


def load_policy(path: str) -> tuple[list[str], list[str], dict[str, str]]:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or set(document) != {"schema_version", "kotlin_roots", "native_roots", "allowed"}:
        raise PolicyError(f"{path}: expected schema_version, kotlin_roots, native_roots and allowed")
    if document["schema_version"] != 1:
        raise PolicyError(f"{path}: unsupported schema_version {document['schema_version']}")
    roots = {}
    for key in ("kotlin_roots", "native_roots"):
        value = document[key]
        if not isinstance(value, list) or not value or not all(isinstance(root, str) and root for root in value):
            raise PolicyError(f"{key} must be a non-empty list of directory patterns")
        roots[key] = value
    allowed: dict[str, str] = {}
    for entry in document["allowed"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "reason"}:
            raise PolicyError("each allowed entry needs exactly path and reason")
        path_value, reason = entry["path"], entry["reason"]
        if not isinstance(path_value, str) or not path_value:
            raise PolicyError("allowed entry path must be a non-empty string")
        if path_value in allowed:
            raise PolicyError(f"{path_value} is allowed twice")
        if not isinstance(reason, str) or not reason.strip():
            raise PolicyError(f"{path_value}: an allowed entry must state a reason")
        allowed[path_value] = reason
    return roots["kotlin_roots"], roots["native_roots"], allowed


def iter_sources(repo_root: str, patterns: list[str], suffixes: tuple[str, ...]):
    seen: set[str] = set()
    for pattern in patterns:
        for base in sorted(glob.glob(os.path.join(repo_root, pattern))):
            for directory, subdirectories, files in os.walk(base):
                subdirectories[:] = sorted(name for name in subdirectories if name not in SKIPPED_DIRECTORIES)
                for name in sorted(files):
                    if name.endswith(suffixes):
                        path = os.path.join(directory, name)
                        relative = os.path.relpath(path, repo_root).replace(os.sep, "/")
                        if relative not in seen:
                            seen.add(relative)
                            yield relative, path


def check(repo_root: str, kotlin_roots: list[str], native_roots: list[str], allowed: dict[str, str]):
    errors: list[str] = []
    report: dict[str, list[tuple[int, str]]] = {}
    for native, roots, suffixes in ((False, kotlin_roots, KOTLIN_SUFFIXES), (True, native_roots, NATIVE_SUFFIXES)):
        for relative, path in iter_sources(repo_root, roots, suffixes):
            with open(path, encoding="utf-8") as handle:
                uses = find_uses(handle.read(), native)
            if uses:
                report[relative] = uses
            if uses and relative not in allowed:
                for line, label in uses:
                    errors.append(f"{relative}:{line}: {label}")
    for relative in sorted(set(allowed) - set(report)):
        if os.path.isfile(os.path.join(repo_root, relative)):
            errors.append(f"{relative}: allowlisted but no longer reads text; remove it from the allowlist")
        else:
            errors.append(f"{relative}: allowlisted but does not exist")
    return errors, report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    parser.add_argument("--repo-root", default=default_root)
    parser.add_argument("--policy", default=None, help="defaults to .github/policies/text-protocols.json")
    parser.add_argument("--report", action="store_true", help="list every text-reading line and exit")
    arguments = parser.parse_args(argv)
    repo_root = os.path.abspath(arguments.repo_root)
    policy_path = arguments.policy or os.path.join(repo_root, ".github", "policies", "text-protocols.json")
    try:
        kotlin_roots, native_roots, allowed = load_policy(policy_path)
    except (OSError, PolicyError, json.JSONDecodeError) as error:
        print(f"text protocol policy error: {error}", file=sys.stderr)
        return 2
    errors, report = check(repo_root, kotlin_roots, native_roots, allowed)
    if arguments.report:
        for relative, uses in sorted(report.items()):
            print(relative)
            for line, label in uses:
                print(f"    {line}: {label}")
        return 0
    if errors:
        for error in errors:
            print(f"text protocol violation: {error}", file=sys.stderr)
        return 1
    print(f"No text protocols across layers or units; {len(allowed)} reviewed files read text by nature.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
