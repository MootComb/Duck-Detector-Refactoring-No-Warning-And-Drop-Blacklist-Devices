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

package com.eltavine.duckdetector.buildlogic.api

import com.android.build.api.artifact.ScopedArtifact
import com.android.build.api.variant.LibraryAndroidComponentsExtension
import com.android.build.api.variant.ScopedArtifacts
import com.eltavine.duckdetector.buildlogic.libs
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.Copy
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.register

/**
 * Records the public API of an SDK contract module in `api/<module>.api`, and makes `checkPublicApi`
 * fail when the compiled API differs, so a change to what SDK consumers compile against is always a
 * reviewed diff.
 *
 * The dump comes from Kotlin's ABI tools, the engine of the Kotlin Gradle plugin's `abiValidation`,
 * in the same format. `abiValidation` itself cannot yet read Android libraries built with AGP's
 * built-in Kotlin, so this plugin hands the tools the module's release classes from AGP instead.
 */
class DuckDetectorPublicApiPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            val dumpFile = "${project.name}.api"
            val updateTaskPath = "${project.path}:updatePublicApi"
            val abiToolsClasspath = configurations.register("publicApiAbiTools") {
                isCanBeConsumed = false
                isCanBeResolved = true
                dependencies.addLater(libs.findLibrary("kotlin-abi-tools").get())
            }
            val dumpPublicApi = tasks.register<DumpPublicApiTask>("dumpPublicApi") {
                dump.set(layout.buildDirectory.file("public-api/$dumpFile"))
                abiTools.from(abiToolsClasspath)
            }
            pluginManager.withPlugin("org.jetbrains.kotlin.jvm") {
                val main = extensions.getByType<SourceSetContainer>().named("main")
                dumpPublicApi.configure { jvmClasses.from(main.map { it.output.classesDirs }) }
            }
            pluginManager.withPlugin("com.android.library") {
                val androidComponents = extensions.getByType<LibraryAndroidComponentsExtension>()
                androidComponents.onVariants(androidComponents.selector().withBuildType("release")) { variant ->
                    variant.artifacts.forScope(ScopedArtifacts.Scope.PROJECT)
                        .use(dumpPublicApi)
                        .toGet(ScopedArtifact.CLASSES, DumpPublicApiTask::classJars, DumpPublicApiTask::classDirectories)
                }
            }
            val checkPublicApi = tasks.register<CheckPublicApiTask>("checkPublicApi") {
                actual.set(dumpPublicApi.flatMap { it.dump })
                reference.from(layout.projectDirectory.file("api/$dumpFile"))
                updateTask.set(updateTaskPath)
                abiTools.from(abiToolsClasspath)
            }
            tasks.register<Copy>("updatePublicApi") {
                from(dumpPublicApi.flatMap { it.dump })
                into(layout.projectDirectory.dir("api"))
            }
            tasks.named("check") { dependsOn(checkPublicApi) }
        }
    }
}
