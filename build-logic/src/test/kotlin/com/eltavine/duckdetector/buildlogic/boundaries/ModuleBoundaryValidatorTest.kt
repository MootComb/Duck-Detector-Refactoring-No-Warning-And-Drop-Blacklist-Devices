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

import com.eltavine.duckdetector.buildlogic.boundaries.PolicyFixtures.layer
import com.eltavine.duckdetector.buildlogic.boundaries.PolicyFixtures.policy
import com.eltavine.duckdetector.buildlogic.boundaries.PolicyFixtures.withLayer
import com.eltavine.duckdetector.buildlogic.boundaries.PolicyFixtures.withMember
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ModuleBoundaryValidatorTest {

    @Test
    fun `accepts a layered policy`() {
        assertEquals(emptyList<String>(), ModuleBoundaryValidator.validatePolicy(policy()))
    }

    @Test
    fun `rejects composition root that is not an application`() {
        val members = PolicyFixtures.validMembers + (":app" to PolicyFixtures.Member("android-library", true, emptyList()))
        assertPolicyError(policy(members), "must be an android-application")
    }

    @Test
    fun `rejects a second application, listed or templated`() {
        assertPolicyError(policy(withMember(":core:launcher", "android-application")), "only :app may be one")
        assertPolicyError(
            policy(mutate = withLayer(":feature", "shell", layer("android-application"))),
            "layer :feature:shell is an application but only :app may be one",
        )
    }

    @Test
    fun `rejects allowlists that reference unknown modules`() {
        assertPolicyError(policy(withMember(":core:scan", "jvm", ":core:missing")), "allows unknown module :core:missing")
    }

    @Test
    fun `rejects self dependencies`() {
        assertPolicyError(policy(withMember(":core:scan", "jvm", ":core:scan")), "lists itself")
    }

    @Test
    fun `rejects member dependencies that point back up the direction`() {
        assertPolicyError(
            policy(withMember(":core:scan", "jvm", ":feature:su:domain")),
            ":core:scan may not depend on :feature:su:domain: dependencies point from",
        )
    }

    @Test
    fun `rejects any dependency on the composition root`() {
        assertPolicyError(policy(withMember(":core:scan", "jvm", ":app")), "may not depend on the composition root")
    }

    @Test
    fun `rejects members inside layered groups, because their layer rule governs them`() {
        assertPolicyError(
            policy(withMember(":feature:su:ui", "android-library", ui = true)),
            ":feature:su:ui belongs to layered group :feature",
        )
    }

    @Test
    fun `rejects wrong member path shapes`() {
        assertPolicyError(policy(withMember(":core:scan:impl", "jvm")), "must have the form :core:<unit>")
        assertPolicyError(policy(withMember(":tools:lint", "jvm")), "not in dependency_direction")
    }

    @Test
    fun `rejects pure JVM members depending on Android members`() {
        val members = withMember(":core:platform", "android-library") +
            (":core:scan" to PolicyFixtures.Member("jvm", false, listOf(":core:evidence", ":core:platform")))
        assertPolicyError(policy(members), "pure JVM module and may not depend on android-library :core:platform")
    }

    @Test
    fun `rejects modules that are not UI depending on UI modules`() {
        assertPolicyError(
            policy(withMember(":core:headless", "android-library", ":core:ui")),
            ":core:headless is not a UI module and may not depend on the UI module :core:ui",
        )
    }

    @Test
    fun `rejects member dependency cycles`() {
        assertPolicyError(
            policy(withMember(":core:evidence", "jvm", ":core:scan")),
            "dependency cycle: :core:evidence -> :core:scan -> :core:evidence",
        )
    }

    @Test
    fun `rejects layer templates that are cyclic, unknown or reach into their own group`() {
        assertPolicyError(
            policy(mutate = withLayer(":feature", "domain", layer("jvm", "data"))),
            "layers of :feature form a dependency cycle: data -> domain -> data",
        )
        assertPolicyError(
            policy(mutate = withLayer(":feature", "domain", layer("jvm", "widgets"))),
            "layer :feature:domain may depend on unknown layer widgets",
        )
        assertPolicyError(
            policy(mutate = withLayer(":feature", "domain", layer("jvm", use = listOf(":feature:*:domain")))),
            "layers reach their own unit through may_depend_on",
        )
    }

    @Test
    fun `classifies new layered modules without a policy entry`() {
        val included = PolicyFixtures.validMembers.keys + ":feature:brandnew:domain" + ":feature:brandnew:ui"

        assertEquals(emptyList<String>(), ModuleBoundaryValidator.validateMembership(policy(), included))
    }

    @Test
    fun `reports unclassified and missing modules`() {
        val included = PolicyFixtures.validMembers.keys - ":core:scan" + ":feature:new:widgets" + ":core:ghost"
        val errors = ModuleBoundaryValidator.validateMembership(policy(), included)

        assertEquals(
            listOf(
                ":core:ghost is included in the build but not classified by the boundary policy",
                ":feature:new:widgets is included in the build but not classified by the boundary policy",
                ":core:scan is classified in the boundary policy but not included in the build",
            ),
            errors,
        )
    }

    @Test
    fun `accepts own-unit layers, templated outside modules and UI artifacts in UI modules`() {
        val facts = facts(
            ":feature:su:ui",
            ModuleKind.ANDROID_LIBRARY,
            compose = true,
            projects = mapOf("implementation" to setOf(":feature:su:presentation", ":core:ui")),
            externals = mapOf("implementation" to setOf("androidx.compose.material3:material3")),
        )
        assertEquals(emptyList<String>(), ModuleBoundaryValidator.validateProject(policy(), facts))
    }

    @Test
    fun `rejects own-unit layers the template does not allow in any configuration`() {
        val facts = facts(
            ":feature:su:ui",
            ModuleKind.ANDROID_LIBRARY,
            compose = true,
            projects = mapOf("testImplementation" to setOf(":feature:su:data")),
        )
        assertProjectError(facts, "'ui' layers may only depend on [domain, presentation] of their own unit")
    }

    @Test
    fun `rejects outside modules the layer template does not use`() {
        val facts = facts(
            ":feature:su:domain",
            ModuleKind.JVM,
            projects = mapOf("api" to setOf(":core:scan")),
        )
        assertProjectError(facts, "'domain' layers of :feature may only use [:capability:*:model, :core:evidence]")
    }

    @Test
    fun `rejects dependencies between isolated units even when the layer matches`() {
        val facts = facts(
            ":feature:su:data",
            ModuleKind.ANDROID_LIBRARY,
            projects = mapOf("implementation" to setOf(":feature:tee:domain")),
        )
        assertProjectError(facts, "units of :feature are isolated from each other")
    }

    @Test
    fun `rejects dependencies against the direction from layered modules`() {
        val facts = facts(
            ":capability:probe:android",
            ModuleKind.ANDROID_LIBRARY,
            projects = mapOf("implementation" to setOf(":feature:su:domain")),
        )
        assertProjectError(facts, "dependencies point from :app to :feature to :capability to :core")
    }

    @Test
    fun `checks member dependencies against their patterns`() {
        val allowed = facts(":app", ModuleKind.ANDROID_APPLICATION, compose = true, projects = mapOf("implementation" to setOf(":feature:su:ui")))
        val denied = facts(":app", ModuleKind.ANDROID_APPLICATION, compose = true, projects = mapOf("implementation" to setOf(":capability:probe:android")))

        assertEquals(emptyList<String>(), ModuleBoundaryValidator.validateProject(policy(), allowed))
        assertProjectError(denied, ":app depends on :capability:probe:android through 'implementation', which the boundary policy does not allow")
    }

    @Test
    fun `rejects modules whose plugin does not match their kind`() {
        assertProjectError(facts(":feature:su:domain", ModuleKind.ANDROID_LIBRARY), "classified as jvm but applies android-library")
        assertProjectError(facts(":core:scan", null), "applies no recognised module plugin")
    }

    @Test
    fun `rejects the Compose compiler and UI artifacts outside UI modules`() {
        assertProjectError(
            facts(":feature:su:data", ModuleKind.ANDROID_LIBRARY, compose = true),
            ":feature:su:data is not a UI module but applies the Compose compiler",
        )
        assertProjectError(
            facts(
                ":feature:su:data",
                ModuleKind.ANDROID_LIBRARY,
                externals = mapOf("implementation" to setOf("androidx.compose.runtime:runtime")),
            ),
            "not a UI module but depends on UI artifact androidx.compose.runtime:runtime through 'implementation'",
        )
    }

    @Test
    fun `rejects Android artifacts in pure JVM modules`() {
        val facts = facts(
            ":feature:su:presentation",
            ModuleKind.JVM,
            externals = mapOf("implementation" to setOf("androidx.lifecycle:lifecycle-viewmodel")),
        )
        assertProjectError(facts, "pure JVM module but depends on Android artifact androidx.lifecycle:lifecycle-viewmodel")
    }

    @Test
    fun `rejects unclassified projects and dependencies on unclassified modules`() {
        assertProjectError(facts(":feature:ghost:widgets", ModuleKind.ANDROID_LIBRARY), "not classified")
        assertProjectError(
            facts(":feature:su:data", ModuleKind.ANDROID_LIBRARY, projects = mapOf("implementation" to setOf(":core:ghost"))),
            "depends on :core:ghost through 'implementation', which the boundary policy does not classify",
        )
    }

    private fun facts(
        path: String,
        kind: ModuleKind?,
        compose: Boolean = false,
        projects: Map<String, Set<String>> = emptyMap(),
        externals: Map<String, Set<String>> = emptyMap(),
    ) = ProjectFacts(path, kind, compose, projects, externals)

    private fun assertPolicyError(policy: ModuleBoundaryPolicy, expected: String) {
        val errors = ModuleBoundaryValidator.validatePolicy(policy)
        assertTrue("expected '$expected' in $errors", errors.any { it.contains(expected) })
    }

    private fun assertProjectError(facts: ProjectFacts, expected: String) {
        val errors = ModuleBoundaryValidator.validateProject(policy(), facts)
        assertTrue("expected '$expected' in $errors", errors.any { it.contains(expected) })
    }
}
