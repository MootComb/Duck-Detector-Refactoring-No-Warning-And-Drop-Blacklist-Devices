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

package com.eltavine.duckdetector.buildlogic.boundaries

import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.artifacts.ExternalModuleDependency
import org.gradle.api.artifacts.ProjectDependency
import org.gradle.api.provider.Provider

/**
 * Makes `.github/policies/module-boundaries.json` part of the build contract.
 *
 * Applied to the root project it validates the policy and that every module is classified;
 * applied to a module it rejects any declared project dependency or artifact its rule does not
 * allow, so a forbidden edge fails Gradle configuration rather than waiting for review.
 */
class DuckDetectorModuleBoundariesPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        val policyText = target.providers
            .fileContents(target.rootProject.layout.projectDirectory.file(ModuleBoundaryPolicy.RELATIVE_PATH))
            .asText
        if (target == target.rootProject) {
            val policy = loadPolicy(policyText)
            val modules = target.subprojects.filter { it.buildFile.exists() }.map { it.path }.toSet()
            report(target, ModuleBoundaryValidator.validatePolicy(policy) +
                ModuleBoundaryValidator.validateMembership(policy, modules))
            return
        }
        target.afterEvaluate {
            val policy = loadPolicy(policyText)
            report(this, ModuleBoundaryValidator.validateProject(policy, collectFacts()))
        }
    }

    private fun loadPolicy(policyText: Provider<String>): ModuleBoundaryPolicy {
        val text = policyText.orNull
            ?: throw GradleException("Module boundary policy is missing: ${ModuleBoundaryPolicy.RELATIVE_PATH}")
        return try {
            ModuleBoundaryPolicy.parse(text)
        } catch (error: ModuleBoundaryPolicyException) {
            throw GradleException("Module boundary policy is malformed: ${error.message}", error)
        }
    }

    private fun report(project: Project, errors: List<String>) {
        if (errors.isEmpty()) {
            return
        }
        throw GradleException(
            buildString {
                appendLine("Module boundary violations in ${project.path} (${ModuleBoundaryPolicy.RELATIVE_PATH}):")
                errors.forEach { appendLine("  - $it") }
            },
        )
    }

    private fun Project.collectFacts(): ProjectFacts {
        val kind = when {
            pluginManager.hasPlugin("com.android.application") -> ModuleKind.ANDROID_APPLICATION
            pluginManager.hasPlugin("com.android.library") -> ModuleKind.ANDROID_LIBRARY
            pluginManager.hasPlugin("com.android.fused-library") -> ModuleKind.ANDROID_FUSED_LIBRARY
            pluginManager.hasPlugin("org.jetbrains.kotlin.jvm") -> ModuleKind.JVM
            else -> null
        }
        val projectDependencies = sortedMapOf<String, MutableSet<String>>()
        val externalDependencies = sortedMapOf<String, MutableSet<String>>()
        // External artifacts only matter where they reach the module's own code; tool classpaths such
        // as androidLintTool legitimately carry Android artifacts into pure JVM modules.
        val codeConfigurations = CODE_CLASSPATHS
            .mapNotNull { configurations.findByName(it) }
            .flatMap { it.hierarchy }
            .mapTo(mutableSetOf()) { it.name }
        configurations.forEach { configuration ->
            configuration.dependencies.forEach { dependency ->
                when (dependency) {
                    // AGP wires test variants to the tested variant through a dependency on the
                    // same project; that is not an edge between modules.
                    is ProjectDependency -> if (dependency.path != path) {
                        projectDependencies.getOrPut(configuration.name, ::sortedSetOf) += dependency.path
                    }

                    is ExternalModuleDependency -> if (configuration.name in codeConfigurations) {
                        externalDependencies.getOrPut(configuration.name, ::sortedSetOf) +=
                            "${dependency.group}:${dependency.name}"
                    }
                }
            }
        }
        return ProjectFacts(
            path = path,
            appliedKind = kind,
            appliesCompose = pluginManager.hasPlugin(COMPOSE_COMPILER_PLUGIN),
            projectDependencies = projectDependencies,
            externalDependencies = externalDependencies,
        )
    }

    private companion object {
        const val COMPOSE_COMPILER_PLUGIN = "org.jetbrains.kotlin.plugin.compose"

        val CODE_CLASSPATHS = listOf(
            "compileClasspath",
            "runtimeClasspath",
            "testCompileClasspath",
            "testRuntimeClasspath",
        )
    }
}
