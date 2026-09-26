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

package com.eltavine.duckdetector.buildlogic.assets

import org.gradle.api.GradleException
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class TeeCrlStatusTest {

    @Test
    fun `the fallback floor keeps its entries and gains only remote-only ones`() {
        val remote = """{"entries": {"aa": {"status": "REVOKED"}, "bb": {"status": "SUSPENDED"}}}"""
        val fallback = """{"entries": {"aa": {"status": "KEY_COMPROMISE"}}}"""

        val entries = JSONObject(mergeWithFallback(remote, fallback)).getJSONObject("entries")

        assertEquals("KEY_COMPROMISE", entries.getJSONObject("aa").getString("status"))
        assertEquals("SUSPENDED", entries.getJSONObject("bb").getString("status"))
    }

    @Test
    fun `a remote revocation of the locally flagged serial replaces it and records its source`() {
        val serial = "8616ef30679ed43cc2b43e3c97a2319e"
        val remote = """{"entries": {"00$serial": {"status": "REVOKED"}}}"""
        val fallback = """{"entries": {"$serial": {"status": "LOCAL"}}}"""

        val entries = JSONObject(mergeWithFallback(remote, fallback)).getJSONObject("entries")

        assertEquals("REVOKED", entries.getJSONObject(serial).getString("status"))
        assertEquals("REMOTE", entries.getJSONObject(serial).getString("_duckDetectorSource"))
        assertFalse(entries.has("00$serial"))
    }

    @Test
    fun `feeds without entries are rejected`() {
        listOf("[]", "{}", "not json").forEach { json ->
            assertThrows(json, GradleException::class.java) { validatedStatusJson(json) }
        }
    }
}
