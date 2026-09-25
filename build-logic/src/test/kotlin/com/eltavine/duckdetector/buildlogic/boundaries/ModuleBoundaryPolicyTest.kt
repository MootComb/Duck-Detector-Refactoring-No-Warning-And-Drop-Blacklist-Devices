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
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ModuleBoundaryPolicyTest {

    @Test
    fun `parses members, layer templates and rules`() {
        val policy = PolicyFixtures.policy()

        assertEquals(":app", policy.compositionRoot)
        assertEquals(ModuleKind.JVM, policy.members.getValue(":core:scan").kind)
        assertTrue(policy.members.getValue(":core:ui").ui)
        assertEquals(setOf(":core:evidence"), policy.members.getValue(":core:scan").allowedProjectDependencies)
        val ui = policy.groupLayers.getValue(":feature").getValue("ui")
        assertEquals(setOf("domain", "presentation"), ui.mayDependOn)
        assertEquals(setOf(":core:evidence", ":core:scan", ":core:ui"), ui.mayUse)
        assertTrue(ui.ui)
        assertEquals(listOf(":app", ":feature", ":capability", ":core"), policy.dependencyDirection)
        assertEquals(listOf("androidx.compose.*:*"), policy.uiOnlyDependencies)
    }

    @Test
    fun `classifies layered modules from their path without a member entry`() {
        val policy = PolicyFixtures.policy()

        val data = requireNotNull(policy.classify(":feature:brandnew:data"))
        assertEquals(ModuleKind.ANDROID_LIBRARY, data.kind)
        assertFalse(data.ui)
        assertEquals(setOf("domain"), data.layer?.mayDependOn)
        assertTrue(requireNotNull(policy.classify(":feature:brandnew:ui")).ui)
        assertNull(requireNotNull(policy.classify(":core:scan")).layer)
    }

    @Test
    fun `leaves undeclared layers, wrong depths and unlisted modules unclassified`() {
        val policy = PolicyFixtures.policy()

        assertNull(policy.classify(":feature:su:widgets"))
        assertNull(policy.classify(":feature:su"))
        assertNull(policy.classify(":feature:su:ui:extra"))
        assertNull(policy.classify(":core:ghost"))
        assertNull(policy.classify(":tools:lint"))
    }

    @Test
    fun `rejects unknown top-level keys`() {
        assertRejected("unexpected=[extra]") { it.put("extra", true) }
    }

    @Test
    fun `rejects missing rule keys`() {
        assertRejected("missing=[ui_only_dependencies]") { it.getJSONObject("rules").remove("ui_only_dependencies") }
    }

    @Test
    fun `rejects the previous schema version`() {
        assertRejected("unsupported schema_version 1") { it.put("schema_version", 1) }
    }

    @Test
    fun `rejects unknown module kind`() {
        assertRejected("unknown kind 'kotlin-multiplatform'") {
            it.getJSONObject("members").getJSONObject(":core:evidence").put("kind", "kotlin-multiplatform")
        }
    }

    @Test
    fun `rejects a ui flag that is not a boolean`() {
        assertRejected("member :core:ui.ui must be true or false") {
            it.getJSONObject("members").getJSONObject(":core:ui").put("ui", "yes")
        }
    }

    @Test
    fun `rejects layer rules without may_use`() {
        assertRejected("layer :feature:domain has unexpected shape (missing=[may_use]") {
            it.getJSONObject("rules").getJSONObject("group_layers").getJSONObject(":feature")
                .getJSONObject("domain").remove("may_use")
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

    private fun assertRejected(expectedMessage: String, mutate: (JSONObject) -> Unit) {
        val error = assertThrows(ModuleBoundaryPolicyException::class.java) {
            ModuleBoundaryPolicy.parse(PolicyFixtures.policyJson(mutate = mutate))
        }
        assertTrue("expected '$expectedMessage' in '${error.message}'", error.message!!.contains(expectedMessage))
    }
}
