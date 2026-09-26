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

package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.features.tee.data.repository.DeferredChecks
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateResult
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeReportReducerDeepCheckTest {

    private val reducer = TeeReportReducer()

    @Test
    fun `skipped deep checks read as skipped rather than passed`() {
        val base = baseArtifacts()
        val skipped = DeferredChecks.skipped(base.snapshot, base.timingSideChannel)
        val report = reducer.reduce(
            base.copy(
                pairConsistency = skipped.pairConsistency,
                aesGcm = skipped.aesGcm,
                lifecycle = skipped.lifecycle,
                oversizedChallenge = skipped.oversizedChallenge,
                pureCertificate = skipped.pureCertificate,
                updateSubcomponent = skipped.updateSubcomponent,
                dualAlgorithm = skipped.dualAlgorithm,
            ),
        )

        val checks = report.sections.single { it.title == "Checks" }.items
        listOf(
            "Key pair",
            "AES-GCM",
            "Lifecycle",
            "Oversized challenge",
            "Pure cert",
            "Update path",
            "Dual algorithm",
        ).forEach { title ->
            val row = checks.single { it.title == title }
            assertTrue("$title: ${row.body}", row.body.startsWith("Skipped"))
            assertEquals(title, TeeSignalLevel.INFO, row.level)
        }
        assertEquals(0, report.supplementaryIndicatorCount)
    }

    @Test
    fun `deep checks that threw are not reported as contradictions`() {
        val report = reducer.reduce(
            baseArtifacts().copy(
                pairConsistency = KeyPairConsistencyResult(
                    executed = false,
                    keyMatchesCertificate = false,
                    probeError = "Keystore backend busy",
                    detail = "Keystore backend busy",
                ),
                lifecycle = KeyLifecycleResult(
                    executed = false,
                    created = false,
                    deleteRemovedAlias = false,
                    regeneratedFreshMaterial = false,
                    probeError = "Keystore backend busy",
                    detail = "Keystore backend busy",
                ),
                pureCertificate = PureCertificateResult.notCompleted("Keystore backend busy"),
            ),
        )

        val checks = report.sections.single { it.title == "Checks" }.items
        listOf("Key pair", "Lifecycle", "Pure cert").forEach { title ->
            val row = checks.single { it.title == title }
            assertEquals(title, "Did not complete • Keystore backend busy", row.body)
            assertEquals(title, TeeSignalLevel.INFO, row.level)
        }
        assertEquals(0, report.supplementaryIndicatorCount)
    }

    @Test
    fun `observed key mismatch still fails`() {
        val report = reducer.reduce(
            baseArtifacts().copy(
                pairConsistency = KeyPairConsistencyResult(
                    keyMatchesCertificate = false,
                    detail = "Leaf certificate public key failed to verify locally signed data.",
                ),
            ),
        )

        val row = report.sections.single { it.title == "Checks" }.items.single { it.title == "Key pair" }
        assertEquals(TeeSignalLevel.FAIL, row.level)
        assertEquals(1, report.supplementaryIndicatorCount)
    }
}
