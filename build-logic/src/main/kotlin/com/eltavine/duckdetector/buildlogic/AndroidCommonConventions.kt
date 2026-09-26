/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.eltavine.duckdetector.buildlogic

import com.android.build.api.dsl.CommonExtension
import org.gradle.api.JavaVersion
import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalog
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.getByType
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinAndroidProjectExtension

internal val Project.libs: VersionCatalog
    get() = extensions.getByType<VersionCatalogsExtension>().named("libs")

/** Settings every Android module shares, so applications and libraries cannot drift apart. */
internal fun Project.configureAndroidCommon(extension: CommonExtension) {
    extension.compileSdk = requiredIntGradleProperty("duckdetector.android.compileSdk")
    extension.compileSdkMinor = requiredIntGradleProperty("duckdetector.android.compileSdkMinor")
    extension.buildToolsVersion = requiredGradleProperty("duckdetector.android.buildTools")
    extension.defaultConfig.minSdk = requiredIntGradleProperty("duckdetector.android.minSdk")
    extension.defaultConfig.testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    extension.compileOptions.sourceCompatibility = JavaVersion.VERSION_17
    extension.compileOptions.targetCompatibility = JavaVersion.VERSION_17
    // Every Android module pins the NDK: the module that builds the native libraries compiles with
    // it and the application strips them with it.
    extension.ndkVersion = requiredGradleProperty("duckdetector.android.ndk")
    val cmakeLists = file("src/main/cpp/CMakeLists.txt")
    if (cmakeLists.exists()) {
        extension.externalNativeBuild.cmake.path = cmakeLists
        extension.externalNativeBuild.cmake.version = requiredGradleProperty("duckdetector.android.cmake")
    }

    val lintBaseline = layout.projectDirectory.file("lint-baseline.xml").asFile
    extension.lint.apply {
        if (lintBaseline.exists()) {
            baseline = lintBaseline
        }

        // Translations are contributed after the strings they cover, so a locale that has
        // not caught up yet is a known state of this project rather than a defect. Keeping
        // these reported but non-blocking is what lets every other lint error stay fatal and
        // gate CI, instead of the whole check being switched off because of untranslated UI.
        warning += setOf(
            "ImpliedQuantity",
            "MissingQuantity",
            "MissingTranslation",
        )
    }

    extensions.configure<KotlinAndroidProjectExtension> {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
            moduleName.set(kotlinModuleName())
            if (composesDetectors()) {
                optIn.add(DETECTOR_SPECIFIC_API)
            }
        }
    }
}

/**
 * A Kotlin module name that is unique in the build. The default is the directory name, which the
 * layers of every feature share, so their `META-INF/<name>.kotlin_module` files would collide in
 * the fused SDK AAR and hide the top-level functions of all but one module from its consumers.
 */
internal fun Project.kotlinModuleName(): String = "duckdetector" + path.replace(':', '-')

/**
 * One task name that runs the unit tests every module is expected to keep green: debug unit tests
 * for Android modules and plain tests for JVM modules. CI and local verification call only this.
 */
internal fun Project.registerUnitTestLifecycle(testTask: String) {
    tasks.register("unitTest") {
        group = "verification"
        description = "Runs this module's unit tests."
        dependsOn(testTask)
    }
}
