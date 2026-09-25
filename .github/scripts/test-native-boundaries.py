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

"""Self-test for check-native-boundaries.py using synthetic native trees."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

CHECKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-native-boundaries.py")
NATIVE = "app/src/main/cpp"

CMAKE = """\
function(native_unit target)
    add_library(${target} OBJECT ${ARGN})
endfunction()

set(COMMON_SOURCES
    common/codec.cpp
)

native_unit(unit_common ${COMMON_SOURCES})
native_unit(unit_alpha
    alpha/probe.cpp
)
native_unit(unit_beta beta/scan.cpp)
if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_sources(unit_beta PRIVATE beta/asm/arm64/trap.S)
endif()

add_library(aggregate SHARED)
target_link_libraries(aggregate PRIVATE unit_common unit_alpha unit_beta log)

# The standalone service compiles its own copy of the common sources.
add_library(service SHARED ${COMMON_SOURCES} beta/service/entry.cpp)
"""

JNI_DEFINITION = """
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_alpha_AlphaBridge_nativeProbe(JNIEnv *env, jobject) {
    return nullptr;
}
"""


class NativeBoundaryCheckerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = self._directory.name
        self.policy = {
            "schema_version": 1,
            "source_root": NATIVE,
            "cmake_lists": f"{NATIVE}/CMakeLists.txt",
            "unit_function": "native_unit",
            "aggregate_library": "aggregate",
            "units": {
                "common": {"path": "common", "owner": ":core:native", "target": "unit_common", "may_include": []},
                "alpha": {"path": "alpha", "owner": ":feature:alpha:data", "target": "unit_alpha",
                          "may_include": ["common"]},
                "beta": {"path": "beta", "owner": ":feature:beta:data", "target": "unit_beta",
                         "may_include": ["common"]},
                "service": {"path": "beta/service", "owner": ":feature:beta:data", "target": "service",
                            "may_include": ["common"]},
            },
            "include_exceptions": [],
        }
        self.modules = [":core:native", ":feature:alpha:data", ":feature:beta:data"]
        self.cmake = CMAKE
        self.native("common/codec.h", "#pragma once\n")
        self.native("common/codec.cpp", '#include "common/codec.h"\n')
        self.native("alpha/probe.h", "#pragma once\n")
        self.native("alpha/probe.cpp", '#include "alpha/probe.h"\n#include "common/codec.h"\n#include <jni.h>\n'
                    + JNI_DEFINITION)
        self.native("beta/scan.h", "#pragma once\n")
        self.native("beta/other.h", "#pragma once\n")
        self.native("beta/scan.cpp", '#include "scan.h"\n#include <string>\n')
        self.native("beta/asm/arm64/trap.S", ".globl beta_trap\n")
        self.native("beta/service/entry.cpp", '#include "common/codec.h"\n')
        self.write(
            "feature/alpha/data/src/main/kotlin/com/example/alpha/AlphaBridge.kt",
            "package com.example.alpha\n\nobject AlphaBridge {\n    external fun nativeProbe(): String\n}\n",
        )

    def tearDown(self) -> None:
        self._directory.cleanup()

    def write(self, relative_path: str, content: str) -> None:
        path = os.path.join(self.root, relative_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    def native(self, relative_path: str, content: str) -> None:
        self.write(f"{NATIVE}/{relative_path}", content)

    def append_native(self, relative_path: str, content: str) -> None:
        with open(os.path.join(self.root, NATIVE, relative_path), "a", encoding="utf-8") as handle:
            handle.write(content)

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        self.write(".github/policies/native-boundaries.json", json.dumps(self.policy))
        self.write(".github/policies/module-boundaries.json",
                   json.dumps({"schema_version": 1, "members": {name: {} for name in self.modules}}))
        self.write(f"{NATIVE}/CMakeLists.txt", self.cmake)
        return subprocess.run([sys.executable, CHECKER, "--repo-root", self.root],
                              capture_output=True, text=True, check=False)

    def assert_rejected(self, *expected_messages: str) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for message in expected_messages:
            self.assertIn(message, result.stderr)

    def assert_policy_error(self, expected_message: str) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(expected_message, result.stderr)

    def add_exception(self, unit: str, header: str, reason: str = "shared probe implementation") -> None:
        self.policy["include_exceptions"].append({"unit": unit, "header": header, "reason": reason})

    def test_accepts_conforming_tree(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("4 units", result.stdout)
        self.assertIn("1 JNI exports", result.stdout)

    def test_rejects_include_from_unit_outside_may_include(self) -> None:
        self.append_native("alpha/probe.cpp", '#include "beta/scan.h"\n')
        self.assert_rejected("alpha/probe.cpp:", "unit alpha includes beta/scan.h from unit beta")

    def test_rejects_angle_bracket_include_of_project_header(self) -> None:
        self.append_native("alpha/probe.cpp", "#include <beta/scan.h>\n")
        self.assert_rejected("unit alpha includes beta/scan.h from unit beta")

    def test_rejects_relative_include_escaping_the_unit(self) -> None:
        self.append_native("alpha/probe.cpp", '#include "../beta/scan.h"\n')
        self.assert_rejected("unit alpha includes beta/scan.h from unit beta")

    def test_ignores_includes_inside_comments(self) -> None:
        self.append_native("alpha/probe.cpp", '// #include "beta/scan.h"\n/*\n#include "beta/scan.h"\n*/\n')
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_exception_allows_only_the_named_header(self) -> None:
        self.add_exception("alpha", "beta/scan.h")
        self.append_native("alpha/probe.cpp", '#include "beta/scan.h"\n#include "beta/other.h"\n')
        result = self.run_checker()
        self.assertEqual(result.returncode, 1)
        self.assertIn("includes beta/other.h from unit beta", result.stderr)
        self.assertNotIn("includes beta/scan.h", result.stderr)

    def test_rejects_stale_exception(self) -> None:
        self.add_exception("alpha", "beta/scan.h")
        self.assert_rejected("include exception alpha -> beta/scan.h is stale")

    def test_exception_requires_reason(self) -> None:
        self.add_exception("alpha", "beta/scan.h", reason=" ")
        self.assert_policy_error("must state a reason")

    def test_rejects_unresolved_quoted_include(self) -> None:
        self.append_native("alpha/probe.cpp", '#include "missing.h"\n')
        self.assert_rejected('"missing.h" does not resolve')

    def test_rejects_file_outside_every_unit(self) -> None:
        self.native("stray/helper.cpp", "int helper() { return 0; }\n")
        self.assert_rejected(f"{NATIVE}/stray/helper.cpp belongs to no native unit")

    def test_rejects_missing_unit_directory(self) -> None:
        self.policy["units"]["gamma"] = {"path": "gamma", "owner": ":core:native", "target": "unit_gamma",
                                         "may_include": []}
        self.assert_rejected(f"unit gamma: {NATIVE}/gamma does not exist", "unit_gamma is not declared")

    def test_rejects_owner_missing_from_module_policy(self) -> None:
        self.policy["units"]["alpha"]["owner"] = ":feature:unknown:data"
        self.assert_rejected("owner :feature:unknown:data is not a module")

    def test_rejects_may_include_of_unknown_unit(self) -> None:
        self.policy["units"]["alpha"]["may_include"] = ["common", "delta"]
        self.assert_policy_error("may_include names delta")

    def test_rejects_units_sharing_a_target(self) -> None:
        self.policy["units"]["beta"]["target"] = "unit_alpha"
        self.assert_policy_error("must not share a target")

    def test_rejects_object_unit_compiling_another_units_source(self) -> None:
        self.cmake = self.cmake.replace("    alpha/probe.cpp\n", "    alpha/probe.cpp\n    common/codec.cpp\n")
        self.assert_rejected("unit_alpha of unit alpha compiles common/codec.cpp owned by unit common")

    def test_rejects_standalone_library_compiling_units_it_may_not_include(self) -> None:
        self.cmake = self.cmake.replace("beta/service/entry.cpp)", "beta/service/entry.cpp alpha/probe.cpp)")
        self.assert_rejected("service of unit service compiles alpha/probe.cpp owned by unit alpha")

    def test_rejects_uncompiled_unit_source(self) -> None:
        self.native("alpha/extra.cpp", "int extra() { return 1; }\n")
        self.assert_rejected(f"{NATIVE}/alpha/extra.cpp is not compiled by unit_alpha of unit alpha")

    def test_collects_sources_added_under_conditions(self) -> None:
        self.cmake = self.cmake.replace("    target_sources(unit_beta PRIVATE beta/asm/arm64/trap.S)\n", "")
        self.assert_rejected(f"{NATIVE}/beta/asm/arm64/trap.S is not compiled by unit_beta")

    def test_rejects_object_unit_declared_outside_the_unit_function(self) -> None:
        self.cmake = self.cmake.replace("native_unit(unit_beta beta/scan.cpp)",
                                        "add_library(unit_beta OBJECT beta/scan.cpp)")
        self.assert_rejected("unit target unit_beta must be created by native_unit")

    def test_rejects_aggregate_library_with_own_sources(self) -> None:
        self.cmake = self.cmake.replace("add_library(aggregate SHARED)", "add_library(aggregate SHARED alpha/probe.cpp)")
        self.assert_rejected("aggregate library aggregate must not compile sources itself")

    def test_rejects_aggregate_library_missing_a_unit(self) -> None:
        self.cmake = self.cmake.replace("unit_alpha unit_beta log", "unit_alpha log")
        self.assert_rejected("aggregate library aggregate does not link unit target unit_beta")

    def test_rejects_target_without_a_unit(self) -> None:
        self.cmake += "add_library(extra SHARED alpha/probe.cpp)\n"
        self.assert_rejected("target extra belongs to no native unit")

    def test_rejects_jni_export_outside_the_owning_module(self) -> None:
        self.native("alpha/probe.cpp", '#include "alpha/probe.h"\n')
        self.append_native("beta/scan.cpp", "#include <jni.h>\n" + JNI_DEFINITION)
        self.assert_rejected("binds com.example.alpha.AlphaBridge from :feature:alpha:data, "
                             "but unit beta is owned by :feature:beta:data")

    def test_rejects_malformed_policy(self) -> None:
        del self.policy["aggregate_library"]
        self.assert_policy_error("expected schema_version 1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
