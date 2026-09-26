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

import com.eltavine.duckdetector.capability.attestation.data.AndroidKeyStoreTools

internal fun GrantSelfDomainFullChainSplitProbe.inspectGrantDescriptorCustomAttestation(
    useStrongBox: Boolean,
    selfUid: Int,
    diagnostics: GrantDetectionDiagnosticLog,
): GrantSelfDomainFullChainSplitResult {
    if (useStrongBox) {
        return GrantSelfDomainFullChainSplitResult(
            detail = "Private grant-attest: skipped for StrongBox pass.",
        )
    }
    val keyStore = AndroidKeyStoreTools.loadKeyStore()
    val baselineAlias = "duck_grant_attest_self_base_${System.nanoTime()}"
    val attestAlias = "duck_grant_attest_self_ak_${System.nanoTime()}"
    val subjectAlias = "duck_grant_attest_self_sub_${System.nanoTime()}"
    val binderClient = Keystore2PrivateBinderClient()
    val grantClient = Keystore2PrivateGrantClient(binderClient)
    var session: Keystore2PrivateSession? = null
    var grantCreated = false
    var service: Any? = null
    try {
        service = binderClient.getKeystoreService() ?: return GrantSelfDomainFullChainSplitResult(
            detail = "Private grant-attest: Keystore2 service unavailable.",
        )
        val sessionResult = binderClient.openSession(useStrongBox = false)
        session = sessionResult.session ?: return GrantSelfDomainFullChainSplitResult(
            detail = "Private grant-attest: ${sessionResult.failureReason ?: "private session unavailable"}.",
        )
        runCatching {
            binderClient.generateSigningKey(
                securityLevel = session.securityLevel,
                keyDescriptor = binderClient.createKeyDescriptor(baselineAlias),
                attestationKeyDescriptor = null,
                attest = true,
            )
            binderClient.getKeyEntry(service, binderClient.createKeyDescriptor(baselineAlias))
        }.getOrElse { throwable ->
            diagnostics.addThrowable("grant-attest-baseline-app-read", throwable)
            return GrantSelfDomainFullChainSplitResult(
                detail = "Private grant-attest: baseline APP getKeyEntry unavailable after ordinary private generateKey (${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}).",
            )
        }
        if (!AndroidKeyStoreTools.generateAttestOnlyEcKey(keyStore, attestAlias)) {
            return GrantSelfDomainFullChainSplitResult(
                detail = "Private grant-attest: PURPOSE_ATTEST_KEY generation unavailable.",
            )
        }
        val grantResult = grantClient.grantAliasToUid(service, attestAlias, selfUid)
        grantResult.throwable?.let { diagnostics.addThrowable("grant-attest-grant", it) }
        val grantId = grantResult.grantId
        if (!grantResult.available || grantId == null) {
            return GrantSelfDomainFullChainSplitResult(
                detail = "Private grant-attest: ${grantResult.detail}",
            )
        }
        grantCreated = true
        binderClient.generateSigningKey(
            securityLevel = session.securityLevel,
            keyDescriptor = binderClient.createKeyDescriptor(subjectAlias),
            attestationKeyDescriptor = grantClient.createGrantDescriptor(grantId),
            attest = true,
        )
        val appDescriptor = binderClient.createKeyDescriptor(subjectAlias)
        val appReadFailure = runCatching {
            binderClient.getKeyEntry(service, appDescriptor)
        }.exceptionOrNull()
        if (appReadFailure == null) {
            return GrantSelfDomainFullChainSplitResult(
                executed = true,
                available = true,
                grantIdPresent = true,
                anomalyKind = GrantSelfDomainAnomalyKind.NONE,
                detail = "Private grant-attest: clean APP getKeyEntry after GRANT custom attestation; baseline APP readback ok.",
            )
        }
        diagnostics.addThrowable("grant-attest-app-read", appReadFailure)
        val errorKind = classifyKeystore2PrivateGrantFailure(
            family = grantFailureFamilyOf(appReadFailure),
            message = appReadFailure.message,
            serviceSpecificErrorCode = binderClient.extractServiceSpecificErrorCode(appReadFailure),
        )
        return if (errorKind == Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND) {
            GrantSelfDomainFullChainSplitResult(
                executed = true,
                available = true,
                grantIdPresent = true,
                anomalyKind = GrantSelfDomainAnomalyKind.SELF_GRANT_ATTESTATION_APP_KEY_NOT_FOUND,
                detail = "Private grant-attest: APP getKeyEntry returned KEY_NOT_FOUND after GRANT custom attestation succeeded; baseline APP readback ok.",
            )
        } else {
            GrantSelfDomainFullChainSplitResult(
                grantIdPresent = true,
                detail = "Private grant-attest: APP getKeyEntry failed (${GrantDomainFullChainSplitProbe.describeThrowable(appReadFailure)}).",
            )
        }
    } catch (throwable: Throwable) {
        diagnostics.addThrowable("grant-attest-failure", throwable)
        return GrantSelfDomainFullChainSplitResult(
            detail = "Private grant-attest failed: ${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}",
        )
    } finally {
        session?.let { binderClient.closeSession(it) }
        if (grantCreated && service != null) {
            val ungrantResult = grantClient.revokeAliasGrant(service, attestAlias, selfUid)
            ungrantResult.throwable?.let { diagnostics.addThrowable("grant-attest-revoke", it) }
        }
        AndroidKeyStoreTools.safeDelete(keyStore, subjectAlias)
        AndroidKeyStoreTools.safeDelete(keyStore, baselineAlias)
        AndroidKeyStoreTools.safeDelete(keyStore, attestAlias)
    }
}
