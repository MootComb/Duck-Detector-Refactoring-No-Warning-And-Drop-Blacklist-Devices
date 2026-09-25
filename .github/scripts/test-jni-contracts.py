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

"""Self-test for check-jni-contracts.py using synthetic source trees."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

CHECKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-jni-contracts.py")

KOTLIN_BRIDGE = """
    package com.example.probe

    class ProbeBridge {
        private external fun nativeCollect(): String
    }
"""

NATIVE_BRIDGE = """
    #include <jni.h>

    extern "C" JNIEXPORT jstring JNICALL
    Java_com_example_probe_ProbeBridge_nativeCollect(JNIEnv* env, jobject) {
        return env->NewStringUTF("ok");
    }
"""


class JniContractCheckerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = self._directory.name

    def tearDown(self) -> None:
        self._directory.cleanup()

    def write(self, relative_path: str, content: str) -> None:
        path = os.path.join(self.root, relative_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(textwrap.dedent(content).lstrip("\n"))

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, CHECKER, "--repo-root", self.root],
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_accepted(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def assert_rejected(self, expected_message: str) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(expected_message, result.stderr)

    def write_valid_pair(self, module: str = "feature") -> None:
        self.write(f"{module}/src/main/java/com/example/probe/ProbeBridge.kt", KOTLIN_BRIDGE)
        self.write(f"{module}/src/main/cpp/probe/native_bridge.cpp", NATIVE_BRIDGE)

    def test_accepts_matching_binding(self) -> None:
        self.write_valid_pair()
        self.assert_accepted()

    def test_accepts_declarations_and_definitions_in_different_modules(self) -> None:
        self.write("feature/probe/src/main/kotlin/com/example/probe/ProbeBridge.kt", KOTLIN_BRIDGE)
        self.write("app/src/main/cpp/probe/native_bridge.cpp", NATIVE_BRIDGE)
        self.assert_accepted()

    def test_rejects_tree_without_declarations(self) -> None:
        self.write("app/src/main/cpp/empty.cpp", "int value = 0;\n")
        self.assert_rejected("no JNI declarations were found")

    def test_rejects_missing_native_definition(self) -> None:
        self.write("feature/src/main/java/com/example/probe/ProbeBridge.kt", KOTLIN_BRIDGE)
        self.write("feature/src/main/cpp/empty.cpp", "int value = 0;\n")
        self.assert_rejected("has no native definition named Java_com_example_probe_ProbeBridge_nativeCollect")

    def test_rejects_definition_left_behind_after_package_move(self) -> None:
        self.write(
            "feature/src/main/java/com/example/moved/ProbeBridge.kt",
            KOTLIN_BRIDGE.replace("com.example.probe", "com.example.moved"),
        )
        self.write("feature/src/main/cpp/probe/native_bridge.cpp", NATIVE_BRIDGE)
        self.assert_rejected("has no matching JVM native declaration")

    def test_rejects_duplicate_definitions(self) -> None:
        self.write_valid_pair()
        self.write("feature/src/main/cpp/probe/copy.cpp", NATIVE_BRIDGE)
        self.assert_rejected("is defined 2 times")

    def test_mangles_nested_classes_and_underscores(self) -> None:
        self.write(
            "feature/src/main/java/com/example/probe/Outer.kt",
            """
            package com.example.probe

            class Outer {
                object Inner_Probe {
                    @JvmStatic
                    external fun read_value(): Int
                }
            }
            """,
        )
        self.write(
            "feature/src/main/cpp/probe/nested.cpp",
            """
            #include <jni.h>

            extern "C" {
            JNIEXPORT jint JNICALL
            Java_com_example_probe_Outer_00024Inner_1Probe_read_1value(JNIEnv*, jclass) {
                return 1;
            }
            }
            """,
        )
        self.assert_accepted()

    def test_honours_jvm_name(self) -> None:
        self.write(
            "feature/src/main/java/com/example/probe/ProbeBridge.kt",
            """
            package com.example.probe

            class ProbeBridge {
                @JvmName("nativeCollect")
                private external fun collect(): String
            }
            """,
        )
        self.write("feature/src/main/cpp/probe/native_bridge.cpp", NATIVE_BRIDGE)
        self.assert_accepted()

    def test_multiline_constructor_keeps_class_scope(self) -> None:
        self.write(
            "feature/src/main/java/com/example/probe/ProbeBridge.kt",
            """
            package com.example.probe

            class ProbeBridge(
                private val name: String,
            ) : Any() {
                private external fun nativeCollect(): String
            }
            """,
        )
        self.write("feature/src/main/cpp/probe/native_bridge.cpp", NATIVE_BRIDGE)
        self.assert_accepted()

    def test_rejects_overloaded_natives(self) -> None:
        self.write(
            "feature/src/main/java/com/example/probe/ProbeBridge.kt",
            """
            package com.example.probe

            class ProbeBridge {
                private external fun nativeCollect(): String
                private external fun nativeCollect(flags: Int): String
            }
            """,
        )
        self.write("feature/src/main/cpp/probe/native_bridge.cpp", NATIVE_BRIDGE)
        self.assert_rejected("requires long-form JNI names")

    def test_rejects_internal_external_function(self) -> None:
        self.write(
            "feature/src/main/java/com/example/probe/ProbeBridge.kt",
            KOTLIN_BRIDGE.replace("private external", "internal external"),
        )
        self.write("feature/src/main/cpp/probe/native_bridge.cpp", NATIVE_BRIDGE)
        self.assert_rejected("module-dependent JVM name")

    def test_rejects_companion_object_natives(self) -> None:
        self.write(
            "feature/src/main/java/com/example/probe/ProbeBridge.kt",
            """
            package com.example.probe

            class ProbeBridge {
                companion object {
                    @JvmStatic
                    external fun nativeCollect(): String
                }
            }
            """,
        )
        self.write("feature/src/main/cpp/probe/native_bridge.cpp", NATIVE_BRIDGE)
        self.assert_rejected("companion objects are unsupported")

    def test_rejects_definition_without_c_linkage(self) -> None:
        self.write("feature/src/main/java/com/example/probe/ProbeBridge.kt", KOTLIN_BRIDGE)
        self.write(
            "feature/src/main/cpp/probe/native_bridge.cpp",
            NATIVE_BRIDGE.replace('extern "C" ', ""),
        )
        self.assert_rejected("lacks C linkage")

    def test_rejects_definition_without_export(self) -> None:
        self.write("feature/src/main/java/com/example/probe/ProbeBridge.kt", KOTLIN_BRIDGE)
        self.write(
            "feature/src/main/cpp/probe/native_bridge.cpp",
            NATIVE_BRIDGE.replace("JNIEXPORT ", ""),
        )
        self.assert_rejected("lacks JNIEXPORT")

    def test_rejects_dynamic_registration(self) -> None:
        self.write_valid_pair()
        self.write(
            "feature/src/main/cpp/probe/onload.cpp",
            """
            #include <jni.h>

            jint register_all(JNIEnv* env, jclass type, const JNINativeMethod* methods) {
                return env->RegisterNatives(type, methods, 1);
            }
            """,
        )
        self.assert_rejected("RegisterNatives is not covered")

    def test_ignores_symbols_in_comments_strings_and_prototypes(self) -> None:
        self.write_valid_pair()
        self.write(
            "feature/src/main/cpp/probe/references.cpp",
            """
            #include <jni.h>

            // Java_com_example_probe_ProbeBridge_nativeStale(JNIEnv*, jobject) { }
            /* Java_com_example_probe_ProbeBridge_nativeOther(JNIEnv*, jobject) { } */
            static const char* kName = "Java_com_example_probe_ProbeBridge_nativeQuoted(";
            extern "C" JNIEXPORT jstring JNICALL
            Java_com_example_probe_ProbeBridge_nativeCollect(JNIEnv* env, jobject);
            """,
        )
        self.assert_accepted()

    def test_accepts_java_native_methods(self) -> None:
        self.write(
            "feature/src/main/java/com/example/probe/ProbeBridge.java",
            """
            package com.example.probe;

            public final class ProbeBridge {
                private native String nativeCollect();
            }
            """,
        )
        self.write("feature/src/main/cpp/probe/native_bridge.cpp", NATIVE_BRIDGE)
        self.assert_accepted()

    def test_ignores_test_source_sets(self) -> None:
        self.write_valid_pair()
        self.write(
            "feature/src/test/java/com/example/probe/FakeBridge.kt",
            """
            package com.example.probe

            class FakeBridge {
                private external fun nativeFake(): String
            }
            """,
        )
        self.assert_accepted()


if __name__ == "__main__":
    unittest.main(verbosity=2)
