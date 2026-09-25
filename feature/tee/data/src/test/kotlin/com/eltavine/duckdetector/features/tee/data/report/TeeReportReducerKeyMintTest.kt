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

import com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationNarrativeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataSemanticsResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMintCapabilityResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMintCryptoCapabilityResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GenerateModeParcelFingerprintResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionDeclaration
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionFamily
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionResult
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeReportReducerKeyMintTest {

    private val reducer = TeeReportReducer()

    @Test
    fun `isolated rsa oaep mgf1 failure remains failure`() {
        val report = reducer.reduce(
            baseArtifacts(
                keyMintCapability = KeyMintCapabilityResult(
                    executed = true,
                    crypto = KeyMintCryptoCapabilityResult(
                        rsaOaepMgf1Ok = false,
                        rsaOaepMgf1Detail = "roundTrip=false, decryptedBytes=0.",
                    ),
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.FAIL, report.supplementaryReviewLevel)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "KeyMint crypto" && it.level == TeeSignalLevel.FAIL
        })
    }

    @Test
    fun `rsa oaep unauthorized mgf1 digest remains failure`() {
        val report = reducer.reduce(
            baseArtifacts(
                keyMintCapability = KeyMintCapabilityResult(
                    executed = true,
                    crypto = KeyMintCryptoCapabilityResult(
                        rsaOaepMgf1Sha1Ok = false,
                        rsaOaepMgf1Sha1Detail = "Unauthorized MGF1-SHA1 operation succeeded.",
                    ),
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.FAIL, report.supplementaryReviewLevel)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "KeyMint crypto" && it.level == TeeSignalLevel.FAIL
        })
    }

    @Test
    fun `skipped mgf1 checks do not become crypto failures`() {
        val report = reducer.reduce(
            baseArtifacts(
                keyMintCapability = KeyMintCapabilityResult(
                    executed = true,
                    crypto = KeyMintCryptoCapabilityResult(
                        rsaOaepMgf1Executed = false,
                        rsaOaepMgf1Ok = false,
                        rsaOaepMgf1Detail = "Skipped because security levels disagree.",
                        rsaOaepMgf1Sha1Executed = false,
                        rsaOaepMgf1Sha1Ok = false,
                        rsaOaepMgf1Sha1Detail = "Skipped because security levels disagree.",
                    ),
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "KeyMint crypto" && it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `keymint crypto row hides full diagnostic behind copy payload`() {
        val report = reducer.reduce(
            baseArtifacts(
                keyMintCapability = KeyMintCapabilityResult(
                    executed = true,
                    crypto = KeyMintCryptoCapabilityResult(
                        rsaOaepMgf1Detail = "roundTrip=true, decryptedBytes=20.",
                    ),
                    diagnosticCopyText = "keymint-capability-diagnostic=v1\nrawBegin=true\nerrorCode=-78",
                ),
            ),
        )

        val row = report.sections.single { it.title == "Checks" }.items.single {
            it.title == "KeyMint crypto"
        }
        assertTrue(row.body.contains("RSA-OAEP MGF1 ok"))
        assertTrue(!row.body.contains("errorCode=-78"))
        assertTrue(row.hiddenCopyText?.contains("tee-keymint-crypto-diagnostic=v1") == true)
        assertTrue(row.hiddenCopyText?.contains("rawBegin=true") == true)
        assertTrue(row.hiddenCopyText?.contains("errorCode=-78") == true)
    }

    @Test
    fun `java hook becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                keystore2Hook = Keystore2HookResult(
                    available = true,
                    javaHookDetected = true,
                    detail = "hooked",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Java-hook", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Keystore2" && it.body.contains(
                "Java-style"
            )
        })
    }

    @Test
    fun `metadata semantics anomaly becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                keyMetadataSemantics = KeyMetadataSemanticsResult(
                    executed = true,
                    usesKeyIdDomain = false,
                    aliasCleared = false,
                    detail = "domain=0 alias=test",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.summary.contains("KEY_ID", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Metadata key" && it.body.contains("Descriptor mismatch")
        })
    }

    @Test
    fun `generate mode parcel fingerprint anomaly becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                generateModeParcelFingerprint = Keystore2GenerateModeParcelFingerprintResult(
                    executed = true,
                    available = true,
                    matched = true,
                    diagnosticCopyText = "reply raw hex dump",
                    detail = "malicious-module generate-mode parcel fingerprint observed",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("TEE Simulator generate-mode fingerprint", ignoreCase = true))
        assertTrue(report.signals.take(4).any { it.label == "Signals" })
        assertTrue(report.signals.any {
            it.label == "TEE Simulator generate-mode fingerprint" && it.value == "Matched"
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "TEE Simulator generate-mode fingerprint" &&
                it.body.contains("TEE Simulator generate-mode fingerprint", ignoreCase = true) &&
                it.hiddenCopyText == "reply raw hex dump"
        })
        assertFalse(report.exportText.contains("reply raw hex dump"))
    }

    @Test
    fun `generate mode parcel fingerprint clean state stays out of supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                generateModeParcelFingerprint = Keystore2GenerateModeParcelFingerprintResult(
                    executed = true,
                    available = true,
                    matched = false,
                    diagnosticCopyText = "clean diagnostic",
                    detail = "clean",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "TEE Simulator generate-mode fingerprint" &&
                it.body.contains("No TEE Simulator generate-mode fingerprint observed.", ignoreCase = true) &&
                it.hiddenCopyText == "clean diagnostic"
        })
    }

    @Test
    fun `generate mode parcel fingerprint unavailable state stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                generateModeParcelFingerprint = Keystore2GenerateModeParcelFingerprintResult(
                    executed = false,
                    available = false,
                    diagnosticCopyText = "unavailable diagnostic",
                    detail = "unavailable",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "TEE Simulator generate-mode fingerprint" &&
                it.body.contains("probe unavailable", ignoreCase = true) &&
            it.hiddenCopyText == "unavailable diagnostic"
        })
    }

    @Test
    fun `vintf keymint version mismatch becomes supplementary failure`() {
        val report = reducer.reduce(
            baseArtifacts(
                vintfKeyMintVersion = VintfKeyMintVersionResult(
                    readable = true,
                    anomalyKind = VintfKeyMintVersionAnomalyKind.MISMATCH,
                    declarations = listOf(
                        VintfKeyMintVersionDeclaration(
                            family = VintfKeyMintVersionFamily.KEYMINT_AIDL,
                            sourcePath = "/vendor/etc/vintf/manifest.xml",
                            format = "aidl",
                            halName = "android.hardware.security.keymint",
                            interfaceName = "IKeyMintDevice",
                            instance = "default",
                            vintfVersion = "3",
                            expectedKeymasterVersion = 300,
                            expectedAttestationVersion = 300,
                        ),
                    ),
                    comparedDeclarations = listOf(
                        VintfKeyMintVersionDeclaration(
                            family = VintfKeyMintVersionFamily.KEYMINT_AIDL,
                            sourcePath = "/vendor/etc/vintf/manifest.xml",
                            format = "aidl",
                            halName = "android.hardware.security.keymint",
                            interfaceName = "IKeyMintDevice",
                            instance = "default",
                            vintfVersion = "3",
                            expectedKeymasterVersion = 300,
                            expectedAttestationVersion = 300,
                        ),
                    ),
                    attestationVersion = 400,
                    keymasterVersion = 400,
                    detail = "kind=MISMATCH",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "KeyMint VINTF" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("did not match", ignoreCase = true)
        })
    }

    @Test
    fun `keymint runtime identity mismatch becomes explicit supplementary failure`() {
        val report = reducer.reduce(
            baseArtifacts(
                vintfKeyMintVersion = VintfKeyMintVersionResult(
                    readable = true,
                    anomalyKind = VintfKeyMintVersionAnomalyKind.MISMATCH,
                    attestationVersion = 100,
                    keymasterVersion = 300,
                    detail = "Attestation and keymaster versions disagree on KeyMint runtime identity.",
                ),
            ),
        )

        assertEquals(1, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.FAIL, report.supplementaryReviewLevel)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "KeyMint runtime identity" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("AOSP single-runtime mapping")
        })
    }

    @Test
    fun `importKey retained narrative becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                importKeyRetainedAttestationNarrative = ImportKeyRetainedAttestationNarrativeResult(
                    executed = true,
                    importSupported = true,
                    markerImportBaselineClean = true,
                    originImported = true,
                    retainedNarrativeDetected = true,
                    priorChainLength = 3,
                    postImportChainLength = 2,
                    retainedCertificateCount = 2,
                    originLabel = "IMPORTED",
                    anomalyKind = ImportKeyRetainedAttestationAnomalyKind.IMPORTED_RETAINED_PRIOR_CHAIN,
                    retainedFingerprint = "abc123def456",
                    detail = "kind=IMPORTED_RETAINED_PRIOR_CHAIN, origin=IMPORTED, retained=2",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("ImportKey retained attestation narrative", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "ImportKey narrative" &&
                it.body.contains("Matched", ignoreCase = true) &&
                it.level == TeeSignalLevel.FAIL
        })
    }

    @Test
    fun `stale generated importKey retained narrative becomes supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                importKeyRetainedAttestationNarrative = ImportKeyRetainedAttestationNarrativeResult(
                    executed = true,
                    importSupported = true,
                    markerImportBaselineClean = true,
                    originImported = false,
                    postImportLeafMatchesMarker = false,
                    retainedNarrativeDetected = true,
                    priorChainLength = 3,
                    postImportChainLength = 3,
                    retainedCertificateCount = 3,
                    originLabel = "GENERATED",
                    anomalyKind = ImportKeyRetainedAttestationAnomalyKind.STALE_GENERATED_AFTER_IMPORT,
                    retainedFingerprint = "abc123def456",
                    detail = "kind=STALE_GENERATED_AFTER_IMPORT, origin=GENERATED, retained=3",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "ImportKey narrative" &&
                it.body.contains("Matched", ignoreCase = true) &&
                it.body.contains("STALE_GENERATED_AFTER_IMPORT") &&
                it.level == TeeSignalLevel.FAIL
        })
    }

    @Test
    fun `importKey retained narrative unavailable state stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                importKeyRetainedAttestationNarrative = ImportKeyRetainedAttestationNarrativeResult(
                    executed = false,
                    detail = "Keystore2 getKeyEntry metadata unavailable.",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "ImportKey narrative" &&
                it.body.contains("Unavailable", ignoreCase = true) &&
                it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `importKey unsupported state stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                importKeyRetainedAttestationNarrative = ImportKeyRetainedAttestationNarrativeResult(
                    executed = false,
                    importSupported = false,
                    anomalyKind = ImportKeyRetainedAttestationAnomalyKind.IMPORT_UNSUPPORTED,
                    detail = "ImportKey support gate failed.",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "ImportKey narrative" &&
                it.body.contains("Unavailable", ignoreCase = true) &&
                it.body.contains("ImportKey support gate failed") &&
                it.level == TeeSignalLevel.INFO
        })
    }
}
