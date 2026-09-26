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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VintfManifestParsingTest {

    @Test
    fun `versionless aidl declaration defaults to keymint1`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <interface>
                        <name>IKeyMintDevice</name>
                        <instance>default</instance>
                    </interface>
                </hal>
            </manifest>
            """.trimIndent(),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = emptyList(),
                manifestFiles = listOf(path),
                vendorApiLevelReader = vendorApiLevelReader(202604),
            ).inspect(snapshot(attestationVersion = 100, keymasterVersion = 100))

            assertEquals(VintfKeyMintVersionAnomalyKind.NONE, result.anomalyKind)
            assertEquals("1", result.comparedDeclarations.single().vintfVersion)
        }
    }

    @Test
    fun `hidl fqname preserves version instance association`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="hidl">
                    <name>android.hardware.keymaster</name>
                    <fqname>@4.0::IKeymasterDevice/default</fqname>
                    <fqname>@4.1::IKeymasterDevice/strongbox</fqname>
                </hal>
            </manifest>
            """.trimIndent(),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = emptyList(),
                manifestFiles = listOf(path),
            ).inspect(snapshot(attestationVersion = 4, keymasterVersion = 41))

            assertEquals(VintfKeyMintVersionAnomalyKind.MISMATCH, result.anomalyKind)
            assertEquals(listOf("4.0"), result.comparedDeclarations.map { it.vintfVersion })
            assertTrue(result.declarations.none {
                it.instance == "default" && it.vintfVersion == "4.1"
            })
        }
    }

    @Test
    fun `malformed unrelated vintf fragments do not poison keymint result`() {
        withManifestDirectory(
            mapOf(
                "android.hardware.security.keymint.xml" to """
                    <manifest version="1.0" type="device">
                        <hal format="aidl">
                            <name>android.hardware.security.keymint</name>
                            <version>2</version>
                            <interface>
                                <name>IKeyMintDevice</name>
                                <instance>default</instance>
                            </interface>
                        </hal>
                    </manifest>
                """.trimIndent(),
                "atcmdfwd-saidl.xml" to "/* Copyright */\nnot xml",
                "vendor.qti.qesdsys.service.xml" to "/** Copyright */\nstill not xml",
            ),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = listOf(path),
                manifestFiles = emptyList(),
                vendorApiLevelReader = vendorApiLevelReader(202604),
            ).inspect(snapshot(attestationVersion = 200, keymasterVersion = 200))

            assertEquals(VintfKeyMintVersionAnomalyKind.NONE, result.anomalyKind)
            assertTrue(result.readable)
            assertTrue(result.unreadablePaths.isEmpty())
        }
    }

    @Test
    fun `malformed keymint fragment remains unreadable`() {
        withManifestDirectory(
            mapOf(
                "android.hardware.security.keymint.xml" to """
                    /* Copyright */
                    <manifest version="1.0" type="device">
                        <hal format="aidl">
                            <name>android.hardware.security.keymint</name>
                        </hal>
                    </manifest>
                """.trimIndent(),
            ),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = listOf(path),
                manifestFiles = emptyList(),
            ).inspect(snapshot(attestationVersion = 200, keymasterVersion = 200))

            assertEquals(VintfKeyMintVersionAnomalyKind.UNREADABLE, result.anomalyKind)
            assertTrue(!result.readable)
            assertTrue(result.unreadablePaths.single().contains("keymint"))
        }
    }

    @Test
    fun `vendor api resolver uses direct vendor property first`() {
        val properties = mapOf(
            "ro.vendor.api_level" to "202604",
            "ro.board.api_level" to "202504",
            "ro.product.first_api_level" to "35",
        )

        val result = resolveVendorApiLevel(properties::get)

        assertEquals(202604, result.level)
        assertTrue(result.detail.contains("ro.vendor.api_level"))
    }

    @Test
    fun `vendor api resolver mirrors vts board and product minimum`() {
        val properties = mapOf(
            "ro.vendor.api_level" to "-1",
            "ro.board.api_level" to "202604",
            "ro.product.first_api_level" to "202504",
        )

        val result = resolveVendorApiLevel(properties::get)

        assertEquals(202504, result.level)
        assertTrue(result.detail.contains("min(productApi=202504, boardApi=202604)"))
    }

    @Test
    fun `vendor api resolver uses product when board properties are absent`() {
        val properties = mapOf(
            "ro.product.first_api_level" to "202504",
        )

        val result = resolveVendorApiLevel(properties::get)

        assertEquals(202504, result.level)
        assertTrue(result.detail.contains("boardApi=absent"))
    }

    @Test
    fun `vendor api resolver falls back to build sdk and reports unknown when absent`() {
        assertEquals(
            37,
            resolveVendorApiLevel(mapOf("ro.build.version.sdk" to "37")::get).level,
        )

        val unknown = resolveVendorApiLevel(emptyMap<String, String>()::get)
        assertEquals(null, unknown.level)
        assertTrue(unknown.detail.contains("Missing"))
    }
}
