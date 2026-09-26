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
import os
import sys
from typing import Iterable, Iterator

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from jni_declarations import JvmDeclaration, parse_java, parse_kotlin  # noqa: E402
from jni_definitions import NativeDefinition, parse_native  # noqa: E402

SKIPPED_DIRECTORIES = {".git", ".gradle", ".idea", ".kotlin", ".cxx", "build", "node_modules"}
JVM_SOURCE_SET_DIRECTORIES = {"java", "kotlin"}
NATIVE_SOURCE_SET_DIRECTORIES = {"cpp"}
NATIVE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp")


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
