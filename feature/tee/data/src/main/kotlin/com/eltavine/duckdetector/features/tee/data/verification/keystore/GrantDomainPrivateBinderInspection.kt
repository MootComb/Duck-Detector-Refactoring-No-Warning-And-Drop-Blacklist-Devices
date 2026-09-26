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

import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitProbe.Companion.appendDetail
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitProbe.Companion.compareChains
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitProbe.Companion.matchesPrivateIsolatedCrashSignature

internal suspend fun GrantDomainFullChainSplitProbe.inspectPrivateBinder(
    alias: String,
    diagnostics: GrantDetectionDiagnosticLog,
): GrantDomainFullChainSplitResult {
    val ownerResult = privateGrantClient.readOwnerChain(alias)
    ownerResult.throwable?.let { diagnostics.addThrowable("private-owner-chain", it) }
    if (!ownerResult.available) {
        return GrantDomainFullChainSplitResult(
            detail = ownerResult.detail,
        )
    }
    val ownerChain = ownerResult.chain
    if (ownerChain.certificates.isEmpty()) {
        return GrantDomainFullChainSplitResult(
            detail = "private getKeyEntry(APP) returned an empty certificate chain.",
        )
    }
    val sessionResult = granteeManager.openSession()
    if (!sessionResult.available || sessionResult.session == null) {
        diagnostics.add("private-session", sessionResult.detail)
        return GrantDomainFullChainSplitResult(
            ownerChainLength = ownerChain.certificates.size,
            detail = "Private: isolated grantee unavailable.",
        )
    }
    var grantCreated = false
    return sessionResult.session.use { session ->
        var stageResult = GrantDomainFullChainSplitResult(
            detail = "Private: grant did not complete.",
        )
        try {
            // Owner creates the grant, but isolated readback must use the owner-passed Keystore2
            // binder. That keeps the test focused on cross-domain GRANT visibility, not service lookup.
            // grant 由 owner 创建，但 isolated 回读必须使用 owner 传入的 Keystore2 binder；这样检测聚焦跨域 GRANT 可见性，而非服务查找差异。
            val grantResult = privateGrantClient.grantAliasToUid(alias, session.uid)
            grantResult.throwable?.let { diagnostics.addThrowable("private-grant", it) }
            val grantId = grantResult.grantId
            if (!grantResult.available || grantId == null) {
                val anomalyKind = if (grantResult.errorKind == Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND) {
                    GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN
                } else {
                    GrantDomainAnomalyKind.UNAVAILABLE
                }
                return@use GrantDomainFullChainSplitResult(
                    executed = anomalyKind == GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                    ownerChainLength = ownerChain.certificates.size,
                    granteeUid = session.uid,
                    anomalyKind = anomalyKind,
                    detail = grantResult.detail,
                )
            }
            grantCreated = true
            val keystore2Binder = privateGrantClient.lookupBinder()
            if (keystore2Binder == null) {
                stageResult = GrantDomainFullChainSplitResult(
                    ownerChainLength = ownerChain.certificates.size,
                    granteeUid = session.uid,
                    detail = "isolated binder call blocked: owner keystore2 binder unavailable.",
                )
            } else {
                val granteeResult = session.readGrantedCertificateChain(grantId, keystore2Binder)
                granteeResult.diagnosticCopyText.takeIf { it.isNotBlank() }?.let(diagnostics::addRaw)
                if (!granteeResult.available) {
                    val stackPayload = diagnostics.text()
                    val crashDetected = matchesPrivateIsolatedCrashSignature(stackPayload)
                    stageResult = GrantDomainFullChainSplitResult(
                        executed = crashDetected,
                        ownerChainLength = ownerChain.certificates.size,
                        granteeUid = session.uid,
                        anomalyKind = if (crashDetected) {
                            GrantDomainAnomalyKind.ISOLATED_PRIVATE_READBACK_CRASH
                        } else {
                            GrantDomainAnomalyKind.UNAVAILABLE
                        },
                        detail = if (crashDetected) {
                            "Private: isolated readback crashed after grant succeeded."
                        } else {
                            "Private: readback failed (${visibleGrantDetail(granteeResult.detail)})."
                        },
                        diagnosticCopyText = if (crashDetected) stackPayload else granteeResult.diagnosticCopyText,
                    )
                } else if (granteeResult.chain.certificates.isEmpty()) {
                    stageResult = GrantDomainFullChainSplitResult(
                        ownerChainLength = ownerChain.certificates.size,
                        granteeChainLength = 0,
                        granteeUid = session.uid,
                        detail = "Private: Domain.GRANT certificate chain empty.",
                    )
                } else {
                    val granteeChain = granteeResult.chain
                    val comparison = compareChains(ownerChain, granteeChain)
                    stageResult = GrantDomainFullChainSplitResult(
                        executed = true,
                        available = true,
                        splitDetected = comparison.splitDetected,
                        ownerChainLength = ownerChain.certificates.size,
                        granteeChainLength = granteeChain.certificates.size,
                        mismatchIndex = comparison.mismatchIndex,
                        granteeUid = session.uid,
                        anomalyKind = if (comparison.splitDetected) {
                            GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT
                        } else {
                            GrantDomainAnomalyKind.NONE
                        },
                        detail = if (comparison.splitDetected) {
                            "Private: matched ${comparison.detail}"
                        } else {
                            "Private: clean (${comparison.detail})"
                        },
                    )
                }
            }
        } finally {
            if (grantCreated) {
                // Cleanup is part of the probe contract. If it fails, keep the detection result but
                // append a short visible note and leave the stack trace in hidden diagnostics.
                // cleanup 是检测契约的一部分；失败时保留检测结果，只追加短可见说明，完整堆栈留在隐藏诊断中。
                val ungrantResult = privateGrantClient.revokeAliasGrant(alias, session.uid)
                ungrantResult.throwable?.let { diagnostics.addThrowable("private-revoke", it) }
                if (!ungrantResult.available) {
                    diagnostics.add("private-revoke", ungrantResult.detail)
                    stageResult = stageResult.copy(
                        detail = appendDetail(stageResult.detail, ungrantResult.detail),
                    )
                }
            }
        }
        stageResult
    }
}
