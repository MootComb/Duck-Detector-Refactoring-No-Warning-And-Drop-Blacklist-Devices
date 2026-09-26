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

import com.android.build.api.dsl.FusedLibraryExtension
import com.eltavine.duckdetector.buildlogic.boundaries.ModuleBoundaryPolicy
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.register

private const val SDK_RUNTIME = ":sdk:runtime"

/**
 * Fuses the headless SDK into one AAR: [SDK_RUNTIME] and every project module it is made of, with
 * external libraries left as dependencies in the POM. `publish` writes it to `build/repository`.
 */
class DuckDetectorSdkDistributionPlugin : Plugin<Project> {
    override fun apply(target: Project) = with(target) {
        pluginManager.apply("com.android.fused-library")
        pluginManager.apply("maven-publish")
        pluginManager.apply("duckdetector.module-boundaries")

        extensions.configure<FusedLibraryExtension> {
            minSdk {
                version = release(requiredIntGradleProperty("duckdetector.android.minSdk"))
            }
        }
        val policy = boundaryPolicy()
        headlessSdkModules(policy).forEach { module ->
            dependencies.add("include", dependencies.project(mapOf("path" to module)))
        }

        // The Fused Library plugin creates the publication of its fusedLibraryComponent itself.
        extensions.configure<PublishingExtension> {
            publications.withType(MavenPublication::class.java).configureEach {
                groupId = "com.eltavine.duckdetector"
                artifactId = "duckdetector-sdk"
                version = providers.gradleProperty("duckdetector.sdk.version").getOrElse("0.0.0-SNAPSHOT")
            }
            repositories {
                maven {
                    name = "build"
                    url = uri(layout.buildDirectory.dir("repository"))
                }
            }
        }

        val verify = tasks.register<VerifyFusedSdkTask>("verifySdkAar") {
            group = "verification"
            description = "Fails when the SDK AAR leaves a project module unfused or reaches a UI library."
            dependsOn("report")
            fusedReport.set(layout.buildDirectory.file("reports/fused_library_report/single/report.json"))
            uiOnlyDependencies.set(policy.uiOnlyDependencies)
            verified.set(layout.buildDirectory.file("verifySdkAar/verified.txt"))
        }
        tasks.named("assemble").configure { dependsOn(verify) }
    }
}

private fun Project.boundaryPolicy(): ModuleBoundaryPolicy =
    ModuleBoundaryPolicy.parse(rootProject.file(ModuleBoundaryPolicy.RELATIVE_PATH).readText())

/**
 * Every project module the headless SDK is made of: [SDK_RUNTIME] and each core, capability and
 * detector-unit module that is not UI. Supporting features such as the dashboard are left out, and
 * the boundary policy guarantees that no module that is not UI depends on one that is.
 */
internal fun Project.headlessSdkModules(policy: ModuleBoundaryPolicy): List<String> {
    val detectorUnits = detectorModules(DETECTOR_LAYER).map { it.substringBeforeLast(':') }.toSet()
    return rootProject.subprojects
        .filter { it.buildFile.exists() && it.path != path && it.path != policy.compositionRoot }
        .map { it.path }
        .filter { module -> policy.classify(module)?.ui == false }
        .filter { module -> !module.startsWith(":sdk:") || module == SDK_RUNTIME }
        .filter { module -> !module.startsWith(":feature:") || module.substringBeforeLast(':') in detectorUnits }
        .sorted()
}
