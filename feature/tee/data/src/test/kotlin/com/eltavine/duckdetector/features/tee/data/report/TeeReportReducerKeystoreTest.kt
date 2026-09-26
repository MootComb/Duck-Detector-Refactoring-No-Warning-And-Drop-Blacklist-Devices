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

import com.eltavine.duckdetector.features.tee.data.native.NativeTeeSnapshot
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderChainConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderHookBootstrapResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderPatchModeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.LegacyKeystorePathResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeReportReducerKeystoreTest {

    private val reducer = TeeReportReducer()

    @Test
    fun `list entries mismatch becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                listEntriesConsistency = ListEntriesConsistencyResult(
                    executed = true,
                    containsAlias = true,
                    listedInAliases = false,
                    inconsistent = true,
                    detail = "containsAlias=true, listedInAliases=false",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.summary.contains("containsAlias()/aliases()", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "listEntries" && it.body.contains("mismatch", ignoreCase = true)
        })
    }

    @Test
    fun `binder chain divergence becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                binderChainConsistency = BinderChainConsistencyResult(
                    executed = true,
                    hookInstalled = true,
                    keystoreChainAvailable = true,
                    binderMaterialAvailable = true,
                    activeProbeSecondCycleSucceeded = true,
                    leafMatches = true,
                    chainMatches = false,
                    keystoreChainLength = 3,
                    binderChainLength = 2,
                    detail = "leafMatches=true, chainMatches=false",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Binder chain" && it.body.contains("diverged", ignoreCase = true)
        })
    }

    @Test
    fun `binder hook bootstrap failure becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                binderHookBootstrap = BinderHookBootstrapResult(
                    executed = true,
                    hookInstalled = false,
                    detail = "bootstrap failed",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Binder hook" && it.body.contains("failed", ignoreCase = true)
        })
    }

    @Test
    fun `binder chain delete entry residue is surfaced in checks`() {
        val report = reducer.reduce(
            baseArtifacts(
                binderChainConsistency = BinderChainConsistencyResult(
                    executed = true,
                    hookInstalled = true,
                    keystoreChainAvailable = true,
                    binderMaterialAvailable = true,
                    activeProbeSecondCycleSucceeded = true,
                    chainMatches = true,
                    deleteEntryRemovedAlias = false,
                    detail = "deleteEntryRemovedAlias=false",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Binder chain" && it.body.contains("deleteEntry left alias present", ignoreCase = true)
        })
    }

    @Test
    fun `binder chain repeated active probe failure is surfaced in checks`() {
        val report = reducer.reduce(
            baseArtifacts(
                binderChainConsistency = BinderChainConsistencyResult(
                    executed = true,
                    hookInstalled = true,
                    keystoreChainAvailable = true,
                    binderMaterialAvailable = true,
                    activeProbeRepeated = true,
                    activeProbeSecondCycleSucceeded = false,
                    detail = "cycle2 failed",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Binder chain" && it.body.contains("Repeated active probe failed", ignoreCase = true)
        })
    }

    @Test
    fun `binder chain repeated active probe failure keeps cycle detail`() {
        val report = reducer.reduce(
            baseArtifacts(
                binderChainConsistency = BinderChainConsistencyResult(
                    executed = true,
                    hookInstalled = true,
                    keystoreChainAvailable = true,
                    binderMaterialAvailable = false,
                    activeProbeRepeated = true,
                    activeProbeSecondCycleSucceeded = false,
                    detail = "cycle2 binder material unavailable: Neither getKeyEntry nor generateKey exposed certificate material for the probe alias.",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Binder chain" &&
                it.body.contains("Repeated active probe failed", ignoreCase = true) &&
                it.body.contains("binder material unavailable", ignoreCase = true)
        })
    }

    @Test
    fun `patch mode divergence becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                binderPatchMode = BinderPatchModeResult(
                    executed = true,
                    hookInstalled = true,
                    generateMaterialAvailable = true,
                    keyEntryMaterialAvailable = true,
                    leafDiffers = true,
                    detail = "leafDiffers=true",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Patch mode" && it.body.contains("Leaf differed", ignoreCase = true)
        })
    }

    @Test
    fun `legacy keystore divergence stays supplementary without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                legacyKeystorePath = LegacyKeystorePathResult(
                    executed = true,
                    hookInstalled = true,
                    userCertCaptured = true,
                    caCertCaptured = true,
                    legacyMaterialAvailable = true,
                    chainMatches = false,
                    legacyChainLength = 2,
                    detail = "legacy mismatch",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Legacy keystore" && it.body.contains("diverged", ignoreCase = true)
        })
    }

    @Test
    fun `native got hook becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                native = NativeTeeSnapshot(
                    trickyStoreDetected = true,
                    gotHookDetected = true,
                    trickyStoreMethods = listOf("GOT_HOOK"),
                    trickyStoreDetails = "got hook",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("GOT", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Native" && it.body.contains("GOT hook")
        })
    }

    @Test
    fun `native honeypot detail exposes timer source fallback and affinity diagnostics`() {
        val report = reducer.reduce(
            baseArtifacts(
                native = NativeTeeSnapshot(
                    trickyStoreDetected = true,
                    honeypotDetected = true,
                    trickyStoreMethods = listOf("HONEYPOT"),
                    trickyStoreDetails = "Keystore-style binder honeypot triggered on 2/3 timing runs.",
                    trickyStoreTimerSource = "arm64_cntvct",
                    trickyStoreTimerFallbackReason = "counter self-check failed once; retried with monotonic clock",
                    trickyStoreAffinityStatus = "bound_cpu0",
                    trickyStoreTimingRunCount = 3,
                    trickyStoreTimingSuspiciousRunCount = 2,
                    trickyStoreTimingMedianGapNs = 18420L,
                    trickyStoreTimingGapMadNs = 910L,
                    trickyStoreTimingMedianNoiseFloorNs = 10000L,
                    trickyStoreTimingMedianRatioPercent = 167,
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Native" &&
                    it.body.contains("Honeypot") &&
                    it.body.contains("arm64_cntvct") &&
                    it.body.contains("bound_cpu0") &&
                    it.body.contains("2/3 suspicious runs") &&
                    it.body.contains("18.4us") &&
                    it.body.contains("0.9us") &&
                    it.body.contains("10.0us") &&
                    it.body.contains("1.67x") &&
                    it.body.contains("Keystore-style binder honeypot triggered on 2/3 timing runs.")
        })
    }

    @Test
    fun `native summary still exposes timing comparison when honeypot stays within bounds`() {
        val report = reducer.reduce(
            baseArtifacts(
                native = NativeTeeSnapshot(
                    trickyStoreDetected = false,
                    honeypotDetected = false,
                    trickyStoreDetails = "Keystore-style binder honeypot timing stayed within normal bounds across redundant backends. libc=41234ns, syscall=25011ns, asm=24890ns timer=arm64_cntvct, affinity=bound_cpu0.",
                    trickyStoreTimerSource = "arm64_cntvct",
                    trickyStoreAffinityStatus = "bound_cpu0",
                    trickyStoreTimingRunCount = 3,
                    trickyStoreTimingSuspiciousRunCount = 0,
                    trickyStoreTimingMedianGapNs = 16342L,
                    trickyStoreTimingGapMadNs = 850L,
                    trickyStoreTimingMedianNoiseFloorNs = 10000L,
                    trickyStoreTimingMedianRatioPercent = 166,
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Native" &&
                    it.body.contains("41234ns") &&
                    it.body.contains("25011ns") &&
                    it.body.contains("24890ns") &&
                    it.body.contains("0/3 suspicious runs") &&
                    it.body.contains("16.3us") &&
                    it.body.contains("0.9us") &&
                    it.body.contains("10.0us") &&
                    it.body.contains("1.66x") &&
                    it.body.contains("arm64_cntvct") &&
                    it.body.contains("bound_cpu0")
        })
    }

    @Test
    fun `timing probe warning stays in checks without creating supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                timing = TimingAnomalyResult(
                    suspicious = true,
                    medianMicros = 299,
                    detail = "Timing side-channel diff 0.299ms stayed below the 0.3ms positive threshold.",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.signals.any {
            it.label == "Signals" &&
                    it.value == "0 policy hard • 0 policy review • 0 local" &&
                    it.level == TeeSignalLevel.PASS
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing" &&
                    it.body == "Fast/steady • 299us" &&
                    it.level == TeeSignalLevel.WARN
        })
        assertEquals("Attestation, trust path, and revocation checks line up.", report.summary)
    }

    @Test
    fun `timing probe equality threshold remains non positive in reducer output`() {
        val report = reducer.reduce(
            baseArtifacts(
                timing = TimingAnomalyResult(
                    suspicious = false,
                    medianMicros = 300,
                    detail = "Timing side-channel diff 0.3ms matched the threshold and remained non-positive.",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing" &&
                    it.body == "Median 300us" &&
                    it.level == TeeSignalLevel.INFO
        })
        assertTrue(report.signals.any {
            it.label == "Signals" &&
                    it.value == "0 policy hard • 0 policy review • 0 local" &&
                    it.level == TeeSignalLevel.PASS
        })
    }
}
