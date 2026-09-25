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

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.json.JSONObject

/**
 * Checks the Fused Library report of the SDK AAR.
 *
 * A project module that is not fused would become a POM dependency no consumer can resolve, and a
 * UI library reached through any external dependency would break the promise of a UI-free SDK.
 */
@CacheableTask
abstract class VerifyFusedSdkTask : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val fusedReport: RegularFileProperty

    /** `group:name` globs from the boundary policy's `ui_only_dependencies`. */
    @get:Input
    abstract val uiOnlyDependencies: ListProperty<String>

    @get:OutputFile
    abstract val verified: RegularFileProperty

    @TaskAction
    fun verify() {
        val report = JSONObject(fusedReport.get().asFile.readText())
        val dependencies = report.getJSONArray("dependencies").map { it.toString() }
        val unfused = dependencies.filter { it.startsWith("project ") }
        val uiPatterns = uiOnlyDependencies.get().map { pattern ->
            Regex(pattern.split("*").joinToString(".*") { Regex.escape(it) })
        }
        val ui = dependencies.filterNot { it.startsWith("project ") }.filter { coordinate ->
            val groupAndName = coordinate.split(":").take(2).joinToString(":")
            uiPatterns.any { it.matches(groupAndName) }
        }
        if (unfused.isNotEmpty() || ui.isNotEmpty()) {
            throw GradleException(
                buildString {
                    appendLine("The SDK AAR is not self-contained and UI-free:")
                    unfused.forEach { appendLine("  - $it is a dependency but is not fused into the AAR") }
                    ui.forEach { appendLine("  - $it is a UI library but reaches the SDK") }
                },
            )
        }
        val included = report.getJSONArray("included").length()
        verified.get().asFile.writeText("$included modules fused, ${dependencies.size} external dependencies\n")
    }
}
