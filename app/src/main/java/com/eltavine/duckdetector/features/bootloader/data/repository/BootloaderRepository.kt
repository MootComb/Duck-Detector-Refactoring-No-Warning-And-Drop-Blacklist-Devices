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

package com.eltavine.duckdetector.features.bootloader.data.repository

import android.content.Context
import com.eltavine.duckdetector.capability.attestation.data.AndroidAttestationCollector
import com.eltavine.duckdetector.capability.attestation.data.AttestationSnapshot
import com.eltavine.duckdetector.capability.attestation.data.BootConsistencyProbe
import com.eltavine.duckdetector.capability.attestation.data.BootConsistencyResult
import com.eltavine.duckdetector.capability.attestation.data.CertificateTrustAnalyzer
import com.eltavine.duckdetector.capability.attestation.data.GoogleAttestationRootStore
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.capability.systemproperties.data.SystemPropertyConsistencyUtils
import com.eltavine.duckdetector.capability.systemproperties.data.SystemPropertyReadUtils
import com.eltavine.duckdetector.capability.systemproperties.domain.MultiSourcePropertyRead
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySource
import com.eltavine.duckdetector.features.bootloader.data.rules.BootloaderCatalog
import com.eltavine.duckdetector.features.bootloader.data.widevine.WidevineBootContext
import com.eltavine.duckdetector.features.bootloader.data.widevine.WidevineBootloaderEvidence
import com.eltavine.duckdetector.features.bootloader.data.widevine.WidevineCredentialRepository
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderEvidenceMode
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderReport
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderStage
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class BootloaderRepository(
    context: Context,
    private val collector: AndroidAttestationCollector = AndroidAttestationCollector(),
    private val readUtils: SystemPropertyReadUtils = SystemPropertyReadUtils(),
    private val consistencyUtils: SystemPropertyConsistencyUtils = SystemPropertyConsistencyUtils(),
) {

    private val appContext = context.applicationContext
    private val trustAnalyzer = CertificateTrustAnalyzer(GoogleAttestationRootStore(appContext))
    private val bootConsistencyProbe = BootConsistencyProbe()
    private val widevineCredentialRepository = WidevineCredentialRepository()

    suspend fun scan(): BootloaderReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                BootloaderReport.failed(throwable.message ?: "Bootloader scan failed.")
            }
    }

    private fun scanInternal(): BootloaderReport {
        val trackedProperties = buildTrackedProperties()
        val coreProperties = BootloaderCatalog.properties.mapTo(linkedSetOf()) { it.property }
        val nativeSnapshot = readUtils.collectNativeSnapshot(trackedProperties.keys)
        val propertyCache = linkedMapOf<String, MultiSourcePropertyRead>()
        val readsByProperty = trackedProperties.mapValues { (property, category) ->
            readUtils.readProperty(
                property = property,
                category = category,
                cache = propertyCache,
                nativeSnapshot = nativeSnapshot,
            )
        }

        val attestation = collector.collect(useStrongBox = false)
        val trust = trustAnalyzer.inspect(attestation.rawCertificates)
        val bootConsistency = bootConsistencyProbe.inspect(attestation)
        val propertyContext = BootloaderPropertyContext.from(readsByProperty)
        val evidenceMode = resolveEvidenceMode(attestation, propertyContext)
        val state = resolveState(attestation, propertyContext)
        val widevineEvidence = widevineCredentialRepository.inspect(
            WidevineBootContext(
                rootOfTrustUnlocked = isRootOfTrustUnlocked(attestation),
                bootStateAppearsLocked = state == BootloaderState.VERIFIED ||
                    state == BootloaderState.SELF_SIGNED ||
                    state == BootloaderState.LOCKED_UNKNOWN,
            ),
        )
        val sourceSignals = consistencyUtils.buildSourceMismatchSignals(readsByProperty.values)
        val consistencySignals = consistencyUtils.buildConsistencySignals(
            readsByProperty = readsByProperty,
            nativeSnapshot = nativeSnapshot,
        )

        val findings = buildList {
            addAll(buildStateFindings(state, evidenceMode, attestation, trust, propertyContext))
            addAll(buildAttestationFindings(attestation, trust))
            addAll(buildPropertyFindings(propertyContext, readsByProperty))
            addAll(
                buildConsistencyFindings(
                    bootConsistency,
                    sourceSignals,
                    consistencySignals,
                    widevineEvidence,
                ),
            )
        }
        val impacts = buildImpacts(
            state = state,
            evidenceMode = evidenceMode,
            trust = trust,
            propertyContext = propertyContext,
            bootConsistency = bootConsistency,
            findings = findings,
            widevineEvidence = widevineEvidence,
        )
        val observedPropertyCount = readsByProperty
            .filterKeys { it in coreProperties }
            .values
            .count { it.preferredValue.isNotBlank() }
        val reflectionHitCount = readsByProperty
            .filterKeys { it in coreProperties }
            .values
            .count {
                it.sourceValues[SystemPropertySource.REFLECTION].isNullOrBlank().not()
            }
        val getpropHitCount = readsByProperty
            .filterKeys { it in coreProperties }
            .values
            .count {
                it.sourceValues[SystemPropertySource.GETPROP].isNullOrBlank().not()
            }
        val methods = buildMethods(
            evidenceMode = evidenceMode,
            attestation = attestation,
            trust = trust,
            bootConsistency = bootConsistency,
            nativeSnapshot = nativeSnapshot,
            observedPropertyCount = observedPropertyCount,
            reflectionHitCount = reflectionHitCount,
            getpropHitCount = getpropHitCount,
            sourceSignals = sourceSignals,
            consistencySignals = consistencySignals,
            propertyContext = propertyContext,
            widevineEvidence = widevineEvidence,
        )

        if (findings.isEmpty() && observedPropertyCount == 0) {
            attestation.errorMessage?.let { return BootloaderReport.failed(it) }
        }

        return BootloaderReport(
            stage = BootloaderStage.READY,
            state = state,
            evidenceMode = evidenceMode,
            trustRoot = trust.trustRoot,
            tier = attestation.tier,
            attestationAvailable = hasAttestation(attestation),
            hardwareBacked = attestation.tier == TeeTier.TEE || attestation.tier == TeeTier.STRONGBOX,
            attestationChainLength = trust.chainLength,
            checkedPropertyCount = BootloaderCatalog.properties.size,
            observedPropertyCount = observedPropertyCount,
            nativePropertyHitCount = nativeSnapshot.nativePropertyHitCount,
            rawBootParamHitCount = nativeSnapshot.bootParamHitCount,
            sourceMismatchCount = sourceSignals.size,
            consistencyFindingCount = bootloaderConsistencyCount(
                bootConsistency,
                sourceSignals,
                consistencySignals,
                widevineEvidence,
            ),
            findings = findings,
            impacts = impacts,
            methods = methods,
            errorMessage = attestation.errorMessage,
        )
    }

    private fun buildTrackedProperties(): Map<String, SystemPropertyCategory> {
        return buildMap {
            BootloaderCatalog.properties.forEach { spec ->
                put(spec.property, spec.category)
            }
            put("ro.build.type", SystemPropertyCategory.BUILD_PROFILE)
            put("ro.build.tags", SystemPropertyCategory.BUILD_PROFILE)
            put("ro.build.fingerprint", SystemPropertyCategory.BUILD_PROFILE)
        }
    }

    private fun resolveEvidenceMode(
        attestation: AttestationSnapshot,
        propertyContext: BootloaderPropertyContext,
    ): BootloaderEvidenceMode {
        return when {
            hasAttestation(attestation) -> BootloaderEvidenceMode.ATTESTATION
            propertyContext.hasBootEvidence -> BootloaderEvidenceMode.PROPERTIES_ONLY
            else -> BootloaderEvidenceMode.UNAVAILABLE
        }
    }

    private fun bootloaderConsistencyCount(
        bootConsistency: BootConsistencyResult,
        sourceSignals: List<SystemPropertySignal>,
        consistencySignals: List<SystemPropertySignal>,
        widevineEvidence: WidevineBootloaderEvidence,
    ): Int {
        val bootCount = listOf(
            bootConsistency.vbmetaDigestMismatch,
            bootConsistency.vbmetaDigestMissingWhileAttestedHashPresent,
            bootConsistency.verifiedBootHashAllZeros,
            bootConsistency.verifiedBootKeyAllZeros,
            bootConsistency.verifiedStateUnlockedMismatch,
        ).count { it }
        return bootCount + sourceSignals.size + consistencySignals.size +
            widevineEvidence.anomalyCount
    }

    private fun isRootOfTrustUnlocked(snapshot: AttestationSnapshot): Boolean {
        val rootOfTrust = snapshot.rootOfTrust ?: return false
        return rootOfTrust.deviceLocked == false ||
            rootOfTrust.verifiedBootState.equals("Unverified", ignoreCase = true)
    }
}
