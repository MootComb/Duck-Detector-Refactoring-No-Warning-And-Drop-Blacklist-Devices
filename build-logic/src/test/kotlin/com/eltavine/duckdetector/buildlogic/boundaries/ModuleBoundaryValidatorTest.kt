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

import com.eltavine.duckdetector.buildlogic.boundaries.PolicyFixtures.policy
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
        val members = PolicyFixtures.validMembers + (":app" to ("android-library" to emptyList()))
        assertPolicyError(policy(members), "must be an android-application")
    }

    @Test
    fun `rejects a second application`() {
        assertPolicyError(policy(withMember(":core:launcher", "android-application")), "only :app may be one")
    }

    @Test
    fun `rejects allowlists that reference unknown members`() {
        assertPolicyError(policy(withMember(":core:scan", "jvm", ":core:missing")), "allows unknown member :core:missing")
    }

    @Test
    fun `rejects self dependencies`() {
        assertPolicyError(policy(withMember(":core:scan", "jvm", ":core:scan")), "lists itself")
    }

    @Test
    fun `rejects dependencies that point back up the direction`() {
        assertPolicyError(
            policy(withMember(":core:scan", "jvm", ":feature:su:domain")),
            ":core:scan may not depend on :feature:su:domain: dependencies point from",
        )
    }

    @Test
    fun `rejects any dependency on the composition root`() {
        assertPolicyError(
            policy(withMember(":feature:su:ui", "android-library", ":app")),
            "may not depend on the composition root",
        )
    }

    @Test
    fun `rejects dependencies between isolated units`() {
        val members = withMember(":feature:tee:domain", "jvm") +
            (":feature:su:ui" to ("android-library" to listOf(":feature:su:presentation", ":feature:tee:domain")))
        assertPolicyError(policy(members), "units of :feature are isolated from each other")
    }

    @Test
    fun `rejects dependencies between capabilities`() {
        val members = withMember(":capability:other:model", "jvm") +
            (":capability:probe:model" to ("jvm" to listOf(":capability:other:model")))
        assertPolicyError(policy(members), "units of :capability are isolated from each other")
    }

    @Test
    fun `rejects layer edges the template does not allow`() {
        assertPolicyError(
            policy(withMember(":feature:su:domain", "jvm", ":feature:su:presentation")),
            "'domain' layers may only depend on []",
        )
    }

    @Test
    fun `rejects ui reaching into the data layer`() {
        assertPolicyError(
            policy(withMember(":feature:su:ui", "android-library", ":feature:su:data")),
            "'ui' layers may only depend on",
        )
    }

    @Test
    fun `rejects layer with the wrong module kind`() {
        assertPolicyError(
            policy(withMember(":feature:su:domain", "android-library")),
            "'domain' layers must be jvm",
        )
    }

    @Test
    fun `rejects undeclared layers and wrong path shapes`() {
        assertPolicyError(policy(withMember(":feature:su:widgets", "android-library")), "uses layer 'widgets'")
        assertPolicyError(policy(withMember(":feature:settings", "android-library")), "must have the form :feature:<unit>:<layer>")
        assertPolicyError(policy(withMember(":core:scan:impl", "jvm")), "must have the form :core:<unit>")
        assertPolicyError(policy(withMember(":tools:lint", "jvm")), "not in dependency_direction")
    }

    @Test
    fun `rejects pure JVM modules depending on Android modules`() {
        val members = withMember(":core:ui", "android-library") +
            (":core:scan" to ("jvm" to listOf(":core:evidence", ":core:ui")))
        assertPolicyError(policy(members), "pure JVM module and may not depend on android-library :core:ui")
    }

    @Test
    fun `rejects dependency cycles`() {
        val members = withMember(":core:evidence", "jvm", ":core:scan")
        assertPolicyError(policy(members), "dependency cycle: :core:evidence -> :core:scan -> :core:evidence")
    }

    @Test
    fun `reports unclassified and missing modules`() {
        val included = PolicyFixtures.validMembers.keys - ":core:scan" + ":feature:new:ui"
        val errors = ModuleBoundaryValidator.validateMembership(policy(), included)

        assertEquals(
            listOf(
                ":feature:new:ui is included in the build but not classified in the boundary policy",
                ":core:scan is classified in the boundary policy but not included in the build",
            ),
            errors,
        )
    }

    @Test
    fun `accepts declared dependencies inside the allowlist`() {
        val facts = facts(
            ":feature:su:ui",
            ModuleKind.ANDROID_LIBRARY,
            projects = mapOf("implementation" to setOf(":feature:su:presentation")),
            externals = mapOf("implementation" to setOf("androidx.compose.material3:material3")),
        )
        assertEquals(emptyList<String>(), ModuleBoundaryValidator.validateProject(policy(), facts))
    }

    @Test
    fun `rejects declared dependencies outside the allowlist in any configuration`() {
        val facts = facts(
            ":feature:su:ui",
            ModuleKind.ANDROID_LIBRARY,
            projects = mapOf("testImplementation" to setOf(":feature:su:data")),
        )
        assertProjectError(facts, ":feature:su:ui depends on :feature:su:data through 'testImplementation'")
    }

    @Test
    fun `rejects modules whose plugin does not match their kind`() {
        assertProjectError(
            facts(":feature:su:domain", ModuleKind.ANDROID_LIBRARY),
            "classified as jvm but applies android-library",
        )
        assertProjectError(facts(":core:scan", null), "applies no recognised module plugin")
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
    fun `rejects unclassified projects`() {
        assertProjectError(facts(":feature:ghost:ui", ModuleKind.ANDROID_LIBRARY), "not classified")
    }

    private fun facts(
        path: String,
        kind: ModuleKind?,
        projects: Map<String, Set<String>> = emptyMap(),
        externals: Map<String, Set<String>> = emptyMap(),
    ) = ProjectFacts(path, kind, projects, externals)

    private fun assertPolicyError(policy: ModuleBoundaryPolicy, expected: String) {
        val errors = ModuleBoundaryValidator.validatePolicy(policy)
        assertTrue("expected '$expected' in $errors", errors.any { it.contains(expected) })
    }

    private fun assertProjectError(facts: ProjectFacts, expected: String) {
        val errors = ModuleBoundaryValidator.validateProject(policy(), facts)
        assertTrue("expected '$expected' in $errors", errors.any { it.contains(expected) })
    }
}
