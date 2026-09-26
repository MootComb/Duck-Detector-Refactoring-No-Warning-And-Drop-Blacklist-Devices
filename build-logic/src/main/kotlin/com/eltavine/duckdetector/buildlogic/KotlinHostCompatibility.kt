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

import org.gradle.api.Project
import org.jetbrains.kotlin.gradle.dsl.KotlinBaseExtension
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmCompilerOptions
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

/**
 * Compiles a library for the oldest Kotlin that SDK hosts may use: the language and API version of
 * `duckdetector.kotlin.sdkStdlib`, with that standard library as its dependency, instead of the
 * Kotlin that builds the project. The app is not a library and keeps the newer defaults.
 */
internal fun Project.compileForSdkHosts(extension: KotlinBaseExtension, compilerOptions: KotlinJvmCompilerOptions) {
    val stdlib = requiredGradleProperty("duckdetector.kotlin.sdkStdlib")
    val version = KotlinVersion.fromVersion(stdlib.substringBeforeLast('.'))
    compilerOptions.languageVersion.set(version)
    compilerOptions.apiVersion.set(version)
    extension.coreLibrariesVersion = stdlib
}
