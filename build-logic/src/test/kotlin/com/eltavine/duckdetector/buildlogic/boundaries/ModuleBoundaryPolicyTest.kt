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

import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ModuleBoundaryPolicyTest {

    @Test
    fun `parses members, kinds and rules`() {
        val policy = PolicyFixtures.policy()

        assertEquals(":app", policy.compositionRoot)
        assertEquals(ModuleKind.JVM, policy.members.getValue(":feature:su:domain").kind)
        assertEquals(
            setOf(":feature:su:domain", ":capability:probe:android"),
            policy.members.getValue(":feature:su:data").allowedProjectDependencies,
        )
        assertEquals(setOf("domain", "presentation"), policy.groupLayers.getValue(":feature").getValue("ui").mayDependOn)
        assertEquals(listOf(":app", ":feature", ":capability", ":core"), policy.dependencyDirection)
    }

    @Test
    fun `rejects unknown top-level keys`() {
        assertRejected("unexpected=[extra]") { it.put("extra", true) }
    }

    @Test
    fun `rejects missing rule keys`() {
        assertRejected("missing=[isolated_groups]") { it.getJSONObject("rules").remove("isolated_groups") }
    }

    @Test
    fun `rejects unsupported schema version`() {
        assertRejected("unsupported schema_version 2") { it.put("schema_version", 2) }
    }

    @Test
    fun `rejects unknown module kind`() {
        assertRejected("unknown kind 'kotlin-multiplatform'") {
            it.getJSONObject("members").getJSONObject(":core:evidence").put("kind", "kotlin-multiplatform")
        }
    }

    @Test
    fun `rejects duplicate dependencies`() {
        assertRejected("contains duplicates") {
            it.getJSONObject("members").getJSONObject(":core:scan")
                .put("allowed_project_dependencies", JSONArray(listOf(":core:evidence", ":core:evidence")))
        }
    }

    @Test
    fun `rejects non-string dependency entries`() {
        assertRejected("must be a non-empty string") {
            it.getJSONObject("members").getJSONObject(":core:scan")
                .put("allowed_project_dependencies", JSONArray(listOf(3)))
        }
    }

    @Test
    fun `rejects invalid json`() {
        val error = assertThrows(ModuleBoundaryPolicyException::class.java) {
            ModuleBoundaryPolicy.parse("{ not json")
        }
        assertTrue(error.message!!, error.message!!.contains("not valid JSON"))
    }

    private fun assertRejected(expectedMessage: String, mutate: (org.json.JSONObject) -> Unit) {
        val error = assertThrows(ModuleBoundaryPolicyException::class.java) {
            ModuleBoundaryPolicy.parse(PolicyFixtures.policyJson(mutate = mutate))
        }
        assertTrue("expected '$expectedMessage' in '${error.message}'", error.message!!.contains(expectedMessage))
    }
}
