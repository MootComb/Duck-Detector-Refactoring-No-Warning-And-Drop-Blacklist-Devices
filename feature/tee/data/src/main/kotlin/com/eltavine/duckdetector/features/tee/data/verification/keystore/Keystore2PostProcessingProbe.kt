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

import com.eltavine.duckdetector.capability.attestation.data.AttestationExtensionParser
import com.eltavine.duckdetector.capability.attestation.data.RootOfTrustSnapshot
import com.eltavine.duckdetector.features.tee.data.native.TeeRegisterTimerNativeBridge
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * keystore2 的 generate_key 只在 RkpdProvisioned 分支调用 KeystorePostProcessor::process_certificate_chain
 * 传入 ATTEST_KEY 会走 UserGenerated 分支，永远不经过后处理，这里用同一条私有 binder 路径成对测量两个分支，
 * 既比时间比值，也比 RootOfTrust，因此后处理无法通过“把两边都改掉”来同时抹平
 * keystore2's generate_key only calls KeystorePostProcessor::process_certificate_chain on the RkpdProvisioned
 * arm. Supplying an ATTEST_KEY takes the UserGenerated arm, which has no post-processing hook at all. This
 * probe measures both arms pairwise over one private binder path, comparing timing ratio and RootOfTrust, so
 * post-processing cannot flatten both signals at once.
 */
class Keystore2PostProcessingProbe(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
    private val extensionParser: AttestationExtensionParser = AttestationExtensionParser(),
    private val registerTimerBridge: TeeRegisterTimerNativeBridge = TeeRegisterTimerNativeBridge(),
) {

    fun inspect(useStrongBox: Boolean = false): Keystore2PostProcessingResult {
        val timeSource = StableTimeSource(
            preferRegisterTimer = false,
            registerTimerSource = { registerTimerBridge.readRegisterTimerNs() },
            monotonicSource = { System.nanoTime() },
        )
        val warnings = mutableListOf<String>()

        return runCatching {
            val sessionResult = binderClient.openSession(useStrongBox = useStrongBox)
            val session = sessionResult.session
                ?: throw IllegalStateException(
                    sessionResult.failureReason
                        ?: "Keystore2 private binder proxy session unavailable.",
                )
            val provisioned = mutableListOf<Any>()

            try {
                // WARMUP：第一次 RKP 取证链可能触发 rkpd 拉新证书，必须先吃掉这一次，否则它会污染整个中位数
                // WARMUP: the first RKP-path attestation may make rkpd fetch fresh certificates. Absorb that
                // once up front or it skews the whole median.
                val warmup = generateRkpPathKey(session, provisioned, timeSource)
                val warmupFailureSummary = warmup.failure?.let(binderClient::describeThrowable)
                val reachability = classifyRkpReachability(warmupFailureSummary)
                // rkp_only 开着且 rkpd 硬失败：后面每次 RKP 路径调用都会抛，采样没有意义，直接短路
                // rkp_only is on and the rkpd fetch hard-failed: every later RKP-path call will throw, so sampling is
                // pointless and we short-circuit.
                // 只在"每次调用都必然抛"的情况下短路，任何从 RKP 取 key 冒出来的错误都反推 rkp_only 已开：
                // 未开时这些错误全会变成 Ok(None) 静默回落，根本不会冒到应用这里
                // Short-circuit only when every call must throw. Any error surfacing from RKP key acquisition implies
                // rkp_only is on: with it off every one of them becomes Ok(None) and falls back silently, never
                // reaching the app.
                if (reachability == RkpReachability.RKP_ONLY_HARD_FAILURE) {
                    return@runCatching unavailableResult(
                        kind = Keystore2PostProcessingAnomalyKind.RKP_UNAVAILABLE,
                        detail = "RKP-path generateKey hard-failed, which implies rkp_only is set (reachability=${reachability.name}): $warmupFailureSummary",
                        warnings = warnings,
                    )
                }
                // 无关失败不短路：可能只是一次抖动，记成 warning 继续采样，真是永久性问题时每对都会失败，
                // 最终照样落到 UNMEASURABLE，所以继续不会改变结论，只会救回可恢复的情况
                // An unrelated failure does not short-circuit: it may be a single blip. Warn and keep sampling. If it
                // is genuinely permanent every pair fails and the verdict still lands on UNMEASURABLE, so continuing
                // cannot change the outcome, it only recovers the recoverable cases.
                if (warmupFailureSummary != null) {
                    warnings += "warmup.rkpPath=$warmupFailureSummary"
                }
                var provisioningInfoObserved: Boolean? = warmup.provisioningInfoPresent

                val attestKeyDescriptor = provisionAttestKey(session, provisioned)
                    ?: return@runCatching unavailableResult(
                        kind = Keystore2PostProcessingAnomalyKind.UNMEASURABLE,
                        detail = "Unable to provision a PURPOSE_ATTEST_KEY reference key. The split-path comparison needs one.",
                        warnings = warnings,
                    )

                var rkpRootOfTrust: RootOfTrustSnapshot? = null
                var attestKeyRootOfTrust: RootOfTrustSnapshot? = null
                val rkpSamples = mutableListOf<Double>()
                val attestKeySamples = mutableListOf<Double>()
                var failedPairCount = 0

                repeat(LOOP_COUNT) { index ->
                    val rkpSample = generateRkpPathKey(session, provisioned, timeSource)
                    val attestKeySample = generateAttestKeyPathKey(
                        session = session,
                        attestKeyDescriptor = attestKeyDescriptor,
                        provisioned = provisioned,
                        timeSource = timeSource,
                    )

                    if (rkpSample.failure == null && attestKeySample.failure == null) {
                        rkpSamples += rkpSample.elapsedMillis
                        attestKeySamples += attestKeySample.elapsedMillis
                        if (rkpRootOfTrust == null) {
                            rkpRootOfTrust = rkpSample.rootOfTrust
                        }
                        if (attestKeyRootOfTrust == null) {
                            attestKeyRootOfTrust = attestKeySample.rootOfTrust
                        }
                        // warmup 失败时链形状还没看到，用第一个成功样本补上
                        // If warmup failed the chain shape was never observed. Recover it from the first good sample.
                        if (provisioningInfoObserved == null) {
                            provisioningInfoObserved = rkpSample.provisioningInfoPresent
                        }
                    } else {
                        failedPairCount += 1
                        val failure = rkpSample.failure ?: attestKeySample.failure
                        warnings += "sample.paired[$index]=${failure?.let(binderClient::describeThrowable) ?: "failed"}"
                    }
                }

                val medianRkp = rkpSamples.medianOrNull()
                val medianAttestKey = attestKeySamples.medianOrNull()
                val pairedSampleCount = minOf(rkpSamples.size, attestKeySamples.size)
                val ratio = postProcessingRatio(medianRkp, medianAttestKey)
                val deltaMillis = if (medianRkp != null && medianAttestKey != null) {
                    medianRkp - medianAttestKey
                } else {
                    null
                }
                val divergence = rootOfTrustDivergence(rkpRootOfTrust, attestKeyRootOfTrust)
                val dispersionMillis = pairedDiffDispersionMillis(rkpSamples, attestKeySamples)
                // ProvisioningInfo 的有无表示这次是否真的走了 RKP 密钥，null 表示没读到
                // Presence of ProvisioningInfo indicates whether an RKP key was actually used. Null means unobserved.
                val rkpChainObserved = provisioningInfoObserved
                val kind = classifyPostProcessing(
                    pairedSampleCount = pairedSampleCount,
                    deltaMillis = deltaMillis,
                    divergenceFields = divergence,
                    dispersionMillis = dispersionMillis,
                    rkpChainObserved = rkpChainObserved,
                )

                Keystore2PostProcessingResult(
                    probeRan = true,
                    measurementAvailable = pairedSampleCount > 0,
                    anomalyKind = kind,
                    pairedSampleCount = pairedSampleCount,
                    attemptedPairCount = LOOP_COUNT,
                    failedPairCount = failedPairCount,
                    medianRkpPathMillis = medianRkp,
                    medianAttestKeyPathMillis = medianAttestKey,
                    ratio = ratio,
                    deltaMillis = deltaMillis,
                    dispersionMillis = dispersionMillis,
                    rkpChainObserved = rkpChainObserved,
                    rkpPathRootOfTrust = rkpRootOfTrust.describe(),
                    attestKeyPathRootOfTrust = attestKeyRootOfTrust.describe(),
                    divergentRootOfTrustFields = divergence,
                    warnings = warnings.toList(),
                    detail = buildKeystore2PostProcessingDetail(
                        anomalyKind = kind,
                        medianRkpPathMillis = medianRkp,
                        medianAttestKeyPathMillis = medianAttestKey,
                        ratio = ratio,
                        deltaMillis = deltaMillis,
                        pairedSampleCount = pairedSampleCount,
                        divergentRootOfTrustFields = divergence,
                    ),
                )
            } finally {
                provisioned
                    .distinctBy { System.identityHashCode(it) }
                    .forEach { binderClient.deleteKey(session.service, it) }
                binderClient.closeSession(session)
            }
        }.getOrElse { throwable ->
            unavailableResult(
                kind = Keystore2PostProcessingAnomalyKind.UNMEASURABLE,
                detail = binderClient.describeThrowable(throwable),
                warnings = warnings,
            )
        }
    }

    private fun provisionAttestKey(
        session: Keystore2PrivateSession,
        provisioned: MutableList<Any>,
    ): Any? {
        val requested = binderClient.createKeyDescriptor(alias("attestkey"))
        provisioned += requested
        return runCatching {
            val metadata = binderClient.generateAttestationKey(session.securityLevel, requested)
            binderClient.resolveFollowUpDescriptor(
                requestedDescriptor = requested,
                keyMetadataOrResponse = metadata,
            ).also { provisioned += it }
        }.getOrNull()
    }

    /**
     * attest_key 为 null 且带 challenge：命中 RkpdProvisioned 分支，也就是唯一可能被后处理改写的路径
     * A null attest_key plus a challenge lands on the RkpdProvisioned arm, the only path post-processing can rewrite.
     */
    private fun generateRkpPathKey(
        session: Keystore2PrivateSession,
        provisioned: MutableList<Any>,
        timeSource: StableTimeSource,
    ): PathSample = generateTimedKey(
        session = session,
        attestationKeyDescriptor = null,
        provisioned = provisioned,
        timeSource = timeSource,
        aliasTag = "rkp",
    )

    /**
     * 传入自己的 ATTEST_KEY：命中 UserGenerated 分支，security_level.rs 里这条分支根本没有后处理调用点
     * Supplying our own ATTEST_KEY lands on the UserGenerated arm, which has no post-processing call site at all.
     */
    private fun generateAttestKeyPathKey(
        session: Keystore2PrivateSession,
        attestKeyDescriptor: Any,
        provisioned: MutableList<Any>,
        timeSource: StableTimeSource,
    ): PathSample = generateTimedKey(
        session = session,
        attestationKeyDescriptor = attestKeyDescriptor,
        provisioned = provisioned,
        timeSource = timeSource,
        aliasTag = "attested",
    )

    private fun generateTimedKey(
        session: Keystore2PrivateSession,
        attestationKeyDescriptor: Any?,
        provisioned: MutableList<Any>,
        timeSource: StableTimeSource,
        aliasTag: String,
    ): PathSample {
        val requested = binderClient.createKeyDescriptor(alias(aliasTag))
        provisioned += requested
        return runCatching {
            val start = timeSource.readNs()
            val metadata = binderClient.generateSigningKey(
                securityLevel = session.securityLevel,
                keyDescriptor = requested,
                attestationKeyDescriptor = attestationKeyDescriptor,
                attest = true,
            )
            val elapsed = (timeSource.readNs() - start) / 1_000_000.0
            val followUp = binderClient.resolveFollowUpDescriptor(
                requestedDescriptor = requested,
                keyMetadataOrResponse = metadata,
            )
            provisioned += followUp
            val facts = readChainFacts(session, followUp)
            PathSample(
                elapsedMillis = elapsed,
                rootOfTrust = facts.rootOfTrust,
                provisioningInfoPresent = facts.provisioningInfoPresent,
            )
        }.getOrElse { PathSample(failure = it) }
    }

    private fun readChainFacts(session: Keystore2PrivateSession, descriptor: Any): ChainFacts {
        return runCatching {
            val response = binderClient.getKeyEntryResponse(session.service, descriptor)
                ?: return ChainFacts()
            val factory = CertificateFactory.getInstance("X.509")
            val leaf = binderClient.getCertificateBlob(response)?.let { blob ->
                factory.generateCertificate(ByteArrayInputStream(blob)) as? X509Certificate
            }
            // ProvisioningInfo 挂在 RKP 中间证书上，不在叶子上，所以要看整条链
            // ProvisioningInfo sits on the RKP intermediate rather than the leaf, so the whole chain must be checked.
            val chainCerts = binderClient.getCertificateChainBlob(response)?.let { blob ->
                runCatching {
                    factory.generateCertificates(ByteArrayInputStream(blob))
                        .filterIsInstance<X509Certificate>()
                }.getOrDefault(emptyList())
            } ?: emptyList()
            val provisioningInfoPresent = (listOfNotNull(leaf) + chainCerts).any {
                it.getExtensionValue(PROVISIONING_INFO_OID) != null
            }
            ChainFacts(
                // RootOfTrust 解析不依赖 challenge 校验结果，这里只取 rootOfTrust 字段
                // RootOfTrust parsing does not depend on challenge verification. Only rootOfTrust is used.
                rootOfTrust = leaf?.let { extensionParser.parse(listOf(it), ByteArray(0)).rootOfTrust },
                provisioningInfoPresent = provisioningInfoPresent,
            )
        }.getOrDefault(ChainFacts())
    }

    private data class ChainFacts(
        val rootOfTrust: RootOfTrustSnapshot? = null,
        val provisioningInfoPresent: Boolean? = null,
    )

    private fun unavailableResult(
        kind: Keystore2PostProcessingAnomalyKind,
        detail: String,
        warnings: List<String>,
    ): Keystore2PostProcessingResult = Keystore2PostProcessingResult(
        probeRan = true,
        measurementAvailable = false,
        anomalyKind = kind,
        warnings = warnings.toList(),
        detail = detail,
    )

    private fun alias(tag: String): String = "${ALIAS_PREFIX}_${tag}_${System.nanoTime()}"

    private data class PathSample(
        val elapsedMillis: Double = 0.0,
        val rootOfTrust: RootOfTrustSnapshot? = null,
        val provisioningInfoPresent: Boolean? = null,
        val failure: Throwable? = null,
    )

    companion object {
        private const val ALIAS_PREFIX = "duck_pp"
        private const val LOOP_COUNT = 12
        private const val PROVISIONING_INFO_OID = "1.3.6.1.4.1.11129.2.1.30"
    }
}

private fun RootOfTrustSnapshot?.describe(): String? {
    val snapshot = this ?: return null
    return "deviceLocked=${snapshot.deviceLocked ?: "n/a"}, verifiedBootState=${snapshot.verifiedBootState ?: "n/a"}"
}

private fun List<Double>.medianOrNull(): Double? {
    if (isEmpty()) return null
    val sorted = sorted()
    val middle = sorted.size / 2
    return if (sorted.size % 2 == 1) {
        sorted[middle]
    } else {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    }
}
