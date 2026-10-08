/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.rootmanagers.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RootManagerCatalogTest {

    private val signatures = RootManagerCatalog.signatures

    @Test
    fun `every family is described exactly once`() {
        assertEquals(enumValues<RootManagerFamily>().toList(), signatures.map { it.family })
    }

    @Test
    fun `no package name is claimed by two families`() {
        val packageNames = signatures.flatMap { it.packageNames }

        assertEquals(packageNames.distinct(), packageNames)
    }

    @Test
    fun `no manager key is claimed by two families`() {
        val keys = signatures.flatMap { it.signingCertificates }

        assertEquals(keys.distinct(), keys)
    }

    @Test
    fun `every manager key is a full sha-256 with a plausible certificate length`() {
        signatures.flatMap { it.signingCertificates }.forEach { key ->
            assertTrue(key.sha256, key.sha256.matches(Regex("[0-9a-f]{64}")))
            assertTrue(key.sha256, key.sizeBytes in 500..1024)
        }
    }

    @Test
    fun `manager keys keep the sizes the family kernels publish in hex`() {
        assertEquals(0x033b, certOf(RootManagerFamily.KERNEL_SU).sizeBytes)
        assertEquals(0x3e6, certOf(RootManagerFamily.KERNEL_SU_NEXT).sizeBytes)
        assertEquals(0x35c, certOf(RootManagerFamily.SUKI_SU).sizeBytes)
        assertEquals(0x377, certOf(RootManagerFamily.RE_SUKI_SU).sizeBytes)
    }

    @Test
    fun `a payload never points at two lineages`() {
        val kernelSuLineage = setOf(
            RootManagerFamily.KERNEL_SU,
            RootManagerFamily.KERNEL_SU_NEXT,
            RootManagerFamily.SUKI_SU,
            RootManagerFamily.RE_SUKI_SU,
        )
        val payloadsByLineage = signatures
            .groupBy { if (it.family in kernelSuLineage) "kernelsu" else it.family.name }
            .mapValues { (_, members) -> members.flatMapTo(hashSetOf()) { it.nativePayloads } }
        val all = payloadsByLineage.values.flatten()

        assertEquals(all.distinct(), all)
    }

    @Test
    fun `every family can be matched by at least one strong anchor`() {
        signatures.forEach { signature ->
            assertTrue(
                signature.family.displayName,
                signature.packageNames.isNotEmpty() ||
                    signature.codeNamespaces.isNotEmpty() ||
                    signature.applicationClassSuffixes.isNotEmpty() ||
                    signature.signingCertificates.isNotEmpty() ||
                    signature.nativePayloads.isNotEmpty(),
            )
        }
    }
}
