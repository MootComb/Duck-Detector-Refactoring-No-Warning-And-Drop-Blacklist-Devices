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

"""Fail when Kotlin or Java code uses reflection outside the reviewed allowlist.

Reflection is disabled by default. Two kinds are gated separately because they fail differently:

* operations - member lookup, access overrides, reflective class loading, dynamic proxies,
  java.lang.reflect and kotlin.reflect APIs, and HiddenApiBypass. Probes need these to reach hidden
  platform APIs.
* class_identity - reading a runtime class name. Release builds are minified, so an app class name
  is obfuscated; a class name is only acceptable where the runtime identity is itself the evidence.

Report wording must come from explicit namers such as FailureName, never from class_identity.
Every allowlist entry names the kinds it needs and a reason, and an entry the file no longer needs
is rejected. Class literals used as type tokens and exception types that are merely caught are not
reflection. String literals and comments are ignored, but the expressions inside Kotlin string
templates are scanned, because a reflected name is most often interpolated into a message.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

KINDS = ("operations", "class_identity")
SOURCE_SUFFIXES = (".kt", ".kts", ".java")
SKIPPED_DIRECTORIES = {".git", ".gradle", ".idea", ".kotlin", ".cxx", "build", "node_modules", "__pycache__"}
NOT_REFLECTION = r"(?!(?:InvocationTargetException|UndeclaredThrowableException)\b)"
CLASS_RECEIVER = r"(?:\bjavaClass|::class\.java|\bClass<[^>]*>)"
PATTERNS = {
    "operations": [
        (r"\bClass\s*\.\s*forName\s*\(", "Class.forName"),
        (r"\.loadClass\s*\(", "ClassLoader.loadClass"),
        (r"\.(?:getDeclaredMethods?|getMethods?|getDeclaredFields?|getFields?|getDeclaredConstructors?|"
         r"getConstructors?|getEnclosingMethod)\s*\(", "member lookup"),
        (r"\.(?:declaredMethods|declaredFields|declaredConstructors)\b", "member lookup"),
        (CLASS_RECEIVER + r"\s*\??\.\s*(?:methods|fields|constructors|isArray|interfaces|superclass)\b",
         "member lookup"),
        (r"\.isAccessible\b|\bsetAccessible\s*\(|\.trySetAccessible\s*\(", "access override"),
        (r"\bProxy\s*\.\s*(?:newProxyInstance|isProxyClass|getInvocationHandler)\b|\bInvocationHandler\b",
         "dynamic proxy"),
        (r"\bjava\.lang\.reflect\." + NOT_REFLECTION + r"[A-Za-z]", "java.lang.reflect"),
        (r"\bkotlin\.reflect\.|\.(?:memberProperties|declaredMemberProperties|memberFunctions)\b",
         "kotlin.reflect"),
        (r"\bHiddenApiBypass\b", "HiddenApiBypass"),
        (r"\.(?:parameterTypes|genericParameterTypes|declaringClass)\b", "reflective metadata"),
    ],
    "class_identity": [
        (CLASS_RECEIVER + r"\s*\??\.\s*(?:simpleName|name|canonicalName|typeName)\b", "runtime class name"),
        (r"::class\s*\.\s*(?:simpleName|qualifiedName)\b", "runtime class name"),
        (r"\.getClass\s*\(\s*\)\s*\.\s*(?:getSimpleName|getName|getCanonicalName|getTypeName)\s*\(",
         "runtime class name"),
    ],
}
COMPILED = {kind: [(re.compile(pattern), label) for pattern, label in patterns] for kind, patterns in PATTERNS.items()}


class PolicyError(ValueError):
    pass


def blank_literals(source: str) -> str:
    """Blank comments and literal text, keeping template expressions and line structure."""
    out = list(source)
    length = len(source)

    def blank(start: int, end: int) -> None:
        for position in range(start, min(end, length)):
            if out[position] != "\n":
                out[position] = " "

    def block_comment_end(index: int) -> int:
        depth = 0
        while index < length:
            if source.startswith("/*", index):
                depth += 1
                index += 2
            elif source.startswith("*/", index):
                depth -= 1
                index += 2
                if depth == 0:
                    return index
            else:
                index += 1
        return length

    def string(index: int, raw: bool) -> int:
        while index < length:
            if raw and source.startswith('"""', index):
                while index + 3 < length and source[index + 3] == '"':
                    index += 1
                return index + 3
            character = source[index]
            if not raw and character == '"':
                return index + 1
            if not raw and character == "\\":
                blank(index, index + 2)
                index += 2
                continue
            if source.startswith("${", index):
                index = code(index + 2, inside_template=True) + 1
                continue
            if not raw and character == "\n":
                return index
            blank(index, index + 1)
            index += 1
        return index

    def code(index: int, inside_template: bool) -> int:
        depth = 0
        while index < length:
            if source.startswith("//", index):
                end = source.find("\n", index)
                end = length if end == -1 else end
                blank(index, end)
                index = end
            elif source.startswith("/*", index):
                end = block_comment_end(index)
                blank(index, end)
                index = end
            elif source.startswith('"""', index):
                index = string(index + 3, raw=True)
            elif source[index] == '"':
                index = string(index + 1, raw=False)
            elif source[index] == "'":
                end = index + 1
                while end < length and source[end] not in "'\n":
                    end += 2 if source[end] == "\\" else 1
                blank(index + 1, end)
                index = end + 1
            else:
                if inside_template and source[index] == "{":
                    depth += 1
                elif inside_template and source[index] == "}":
                    if depth == 0:
                        return index
                    depth -= 1
                index += 1
        return index

    code(0, inside_template=False)
    return "".join(out)


def find_uses(source: str) -> dict[str, list[tuple[int, str]]]:
    code = blank_literals(source)
    uses: dict[str, list[tuple[int, str]]] = {kind: [] for kind in KINDS}
    for kind, patterns in COMPILED.items():
        for pattern, label in patterns:
            for match in pattern.finditer(code):
                uses[kind].append((code.count("\n", 0, match.start()) + 1, label))
    for kind in KINDS:
        uses[kind].sort()
    return uses


def load_policy(path: str) -> tuple[list[str], dict[str, tuple[set[str], str]]]:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or set(document) != {"schema_version", "scan_roots", "allowed"}:
        raise PolicyError(f"{path}: expected schema_version, scan_roots and allowed")
    if document["schema_version"] != 1:
        raise PolicyError(f"{path}: unsupported schema_version {document['schema_version']}")
    roots = document["scan_roots"]
    if not isinstance(roots, list) or not roots or not all(isinstance(root, str) and root for root in roots):
        raise PolicyError("scan_roots must be a non-empty list of directories")
    allowed: dict[str, tuple[set[str], str]] = {}
    for entry in document["allowed"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "uses", "reason"}:
            raise PolicyError("each allowed entry needs exactly path, uses and reason")
        path_value, uses, reason = entry["path"], entry["uses"], entry["reason"]
        if not isinstance(path_value, str) or not path_value:
            raise PolicyError("allowed entry path must be a non-empty string")
        if path_value in allowed:
            raise PolicyError(f"{path_value} is allowed twice")
        if not isinstance(uses, list) or not uses or not set(uses) <= set(KINDS) or len(set(uses)) != len(uses):
            raise PolicyError(f"{path_value}: uses must name distinct kinds from {list(KINDS)}")
        if not isinstance(reason, str) or not reason.strip():
            raise PolicyError(f"{path_value}: an allowed entry must state a reason")
        allowed[path_value] = (set(uses), reason)
    return roots, allowed


def iter_sources(repo_root: str, roots: list[str]):
    for root in roots:
        base = os.path.join(repo_root, root)
        for directory, subdirectories, files in os.walk(base):
            subdirectories[:] = sorted(name for name in subdirectories if name not in SKIPPED_DIRECTORIES)
            for name in sorted(files):
                if name.endswith(SOURCE_SUFFIXES):
                    path = os.path.join(directory, name)
                    yield os.path.relpath(path, repo_root).replace(os.sep, "/"), path


def check(repo_root: str, roots: list[str], allowed: dict[str, tuple[set[str], str]]):
    errors: list[str] = []
    report: dict[str, dict[str, list[tuple[int, str]]]] = {}
    for relative, path in iter_sources(repo_root, roots):
        with open(path, encoding="utf-8") as handle:
            uses = find_uses(handle.read())
        used_kinds = {kind for kind in KINDS if uses[kind]}
        if used_kinds:
            report[relative] = uses
        permitted = allowed.get(relative, (set(), ""))[0]
        for kind in sorted(used_kinds - permitted):
            for line, label in uses[kind]:
                errors.append(f"{relative}:{line}: {label} is {kind} reflection outside the allowlist")
        for kind in sorted(permitted - used_kinds):
            errors.append(f"{relative}: allowlisted for {kind} but no longer uses it; remove it from the allowlist")
    for relative in sorted(set(allowed) - set(report)):
        if not os.path.isfile(os.path.join(repo_root, relative)):
            errors.append(f"{relative}: allowlisted but does not exist")
    return errors, report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    parser.add_argument("--repo-root", default=default_root)
    parser.add_argument("--policy", default=None, help="defaults to .github/policies/reflection-allowlist.json")
    parser.add_argument("--report", action="store_true", help="list every reflective use and exit")
    arguments = parser.parse_args(argv)
    repo_root = os.path.abspath(arguments.repo_root)
    policy_path = arguments.policy or os.path.join(repo_root, ".github", "policies", "reflection-allowlist.json")
    try:
        roots, allowed = load_policy(policy_path)
    except (OSError, PolicyError, json.JSONDecodeError) as error:
        print(f"reflection policy error: {error}", file=sys.stderr)
        return 2
    errors, report = check(repo_root, roots, allowed)
    if arguments.report:
        for relative, uses in sorted(report.items()):
            kinds = ", ".join(f"{kind}={len(uses[kind])}" for kind in KINDS if uses[kind])
            labels = sorted({label for kind in KINDS for _, label in uses[kind]})
            print(f"{relative}  [{kinds}]  {'; '.join(labels)}")
        return 0
    if errors:
        for error in errors:
            print(f"reflection violation: {error}", file=sys.stderr)
        return 1
    print(f"Reflection confined to {len(allowed)} reviewed files.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
