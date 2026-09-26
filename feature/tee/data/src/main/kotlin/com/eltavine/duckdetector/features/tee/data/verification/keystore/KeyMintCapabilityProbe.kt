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

import android.os.Build
import android.os.Process
import com.eltavine.duckdetector.capability.attestation.data.AndroidKeyStoreTools

class KeyMintCapabilityProbe(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
) {
    private val rawRsaOaepMgf1 = RawRsaOaepMgf1Checks(binderClient)

    fun inspect(
        attestationVersion: Int? = null,
        keymasterVersion: Int? = null,
        declaredKeyMintVersion: Int? = null,
        legacyKeymasterDeclared: Boolean = false,
        securityLevelsConsistent: Boolean = true,
        runtimeIdentityConsistent: Boolean = true,
        useStrongBox: Boolean = false,
    ): KeyMintCapabilityResult {
        val hmac = hmacSha256(useStrongBox)
        val limitedUseEc = limitedUseEc(useStrongBox)
        val ecdh = ecdhP256(useStrongBox)
        val rsaPss = rsaPssSha256(useStrongBox)
        val aesCbcCtr = aesCbcCtrRejected(useStrongBox)
        val aesCbcNoPadding = aesCbcNoPaddingRejected(useStrongBox)
        val ecSha512 = ecSha512Rejected(useStrongBox)
        val rsaPssSha512 = rsaPssSha512Rejected(useStrongBox)
        val rsaPssPkcs1 = rsaPssPkcs1Rejected(useStrongBox)
        val rsaOaepPkcs1 = rsaOaepPkcs1Rejected(useStrongBox)
        val rsaPkcs1Oaep = rsaPkcs1OaepRejected(useStrongBox)
        val backend = classifyKeyMintBackend(
            attestationVersion = attestationVersion,
            keymasterVersion = keymasterVersion,
            declaredKeyMintVersion = declaredKeyMintVersion,
            legacyKeymasterDeclared = legacyKeymasterDeclared,
            runtimeIdentityConsistent = runtimeIdentityConsistent,
        )
        val rsaOaepMgf1 = rawRsaOaepMgf1.rsaOaepMgf1Sha256(
            backend = backend,
            securityLevelsConsistent = securityLevelsConsistent,
            useStrongBox,
        )
        val rsaOaepMgf1Sha1 = rawRsaOaepMgf1.rsaOaepMgf1Sha1Rejected(
            backend = backend,
            securityLevelsConsistent = securityLevelsConsistent,
            useStrongBox,
        )
        val rsaOaepSha256 = rsaOaepSha256RoundTrip(useStrongBox)
        val rsaOaepSha1 = rsaOaepSha1Rejected(useStrongBox)
        val ecNone = ecNoneRejected(useStrongBox)
        val rsaPkcs1Sha1 = rsaPkcs1Sha1Rejected(useStrongBox)
        val rsaPkcs1Pss = rsaPkcs1PssRejected(useStrongBox)
        val grantUpdateSubcomponent = grantUpdateSubcomponent(useStrongBox)
        val crypto = KeyMintCryptoCapabilityResult(
                hmacSha256Ok = hmac.ok,
                hmacSha256Detail = hmac.detail,
                limitedUseEcExecuted = limitedUseEc.executed,
                limitedUseEcOk = limitedUseEc.ok,
                limitedUseEcDetail = limitedUseEc.detail,
                ecdhP256Executed = ecdh.executed,
                ecdhP256Ok = ecdh.ok,
                ecdhP256Detail = ecdh.detail,
                rsaPssSha256Ok = rsaPss.ok,
                rsaPssSha256Detail = rsaPss.detail,
                aesCbcCtrExecuted = aesCbcCtr.executed,
                aesCbcCtrOk = aesCbcCtr.ok,
                aesCbcCtrDetail = aesCbcCtr.detail,
                aesCbcNoPaddingExecuted = aesCbcNoPadding.executed,
                aesCbcNoPaddingOk = aesCbcNoPadding.ok,
                aesCbcNoPaddingDetail = aesCbcNoPadding.detail,
                ecSha512Executed = ecSha512.executed,
                ecSha512Ok = ecSha512.ok,
                ecSha512Detail = ecSha512.detail,
                rsaPssSha512Executed = rsaPssSha512.executed,
                rsaPssSha512Ok = rsaPssSha512.ok,
                rsaPssSha512Detail = rsaPssSha512.detail,
                rsaPssPkcs1Executed = rsaPssPkcs1.executed,
                rsaPssPkcs1Ok = rsaPssPkcs1.ok,
                rsaPssPkcs1Detail = rsaPssPkcs1.detail,
                rsaOaepPkcs1Executed = rsaOaepPkcs1.executed,
                rsaOaepPkcs1Ok = rsaOaepPkcs1.ok,
                rsaOaepPkcs1Detail = rsaOaepPkcs1.detail,
                rsaPkcs1OaepExecuted = rsaPkcs1Oaep.executed,
                rsaPkcs1OaepOk = rsaPkcs1Oaep.ok,
                rsaPkcs1OaepDetail = rsaPkcs1Oaep.detail,
                rsaOaepMgf1Executed = rsaOaepMgf1.executed,
                rsaOaepMgf1Ok = rsaOaepMgf1.ok,
                rsaOaepMgf1Detail = rsaOaepMgf1.detail,
                rsaOaepMgf1Sha1Executed = rsaOaepMgf1Sha1.executed,
                rsaOaepMgf1Sha1Ok = rsaOaepMgf1Sha1.ok,
                rsaOaepMgf1Sha1Detail = rsaOaepMgf1Sha1.detail,
                rsaOaepSha256Executed = rsaOaepSha256.executed,
                rsaOaepSha256Ok = rsaOaepSha256.ok,
                rsaOaepSha256Detail = rsaOaepSha256.detail,
                rsaOaepSha1Executed = rsaOaepSha1.executed,
                rsaOaepSha1Ok = rsaOaepSha1.ok,
                rsaOaepSha1Detail = rsaOaepSha1.detail,
                ecNoneExecuted = ecNone.executed,
                ecNoneOk = ecNone.ok,
                ecNoneDetail = ecNone.detail,
                rsaPkcs1Sha1Executed = rsaPkcs1Sha1.executed,
                rsaPkcs1Sha1Ok = rsaPkcs1Sha1.ok,
                rsaPkcs1Sha1Detail = rsaPkcs1Sha1.detail,
                rsaPkcs1PssExecuted = rsaPkcs1Pss.executed,
                rsaPkcs1PssOk = rsaPkcs1Pss.ok,
                rsaPkcs1PssDetail = rsaPkcs1Pss.detail,
                grantUpdateSubcomponentExecuted = grantUpdateSubcomponent.executed,
                grantUpdateSubcomponentOk = grantUpdateSubcomponent.ok,
                grantUpdateSubcomponentDetail = grantUpdateSubcomponent.detail,
            )
        return KeyMintCapabilityResult(
            executed = true,
            crypto = crypto,
            diagnosticCopyText = buildKeyMintDiagnosticCopyText(
                sdkInt = Build.VERSION.SDK_INT,
                useStrongBox = useStrongBox,
                attestationVersion = attestationVersion,
                keymasterVersion = keymasterVersion,
                declaredKeyMintVersion = declaredKeyMintVersion,
                legacyKeymasterDeclared = legacyKeymasterDeclared,
                securityLevelsConsistent = securityLevelsConsistent,
                runtimeIdentityConsistent = runtimeIdentityConsistent,
                checks = listOf(
                    KeyMintDiagnosticEntry("HMAC-SHA256", hmac.executed, hmac.ok, hmac.detail, hmac.diagnostic),
                    KeyMintDiagnosticEntry("Single-use EC", limitedUseEc.executed, limitedUseEc.ok, limitedUseEc.detail, limitedUseEc.diagnostic),
                    KeyMintDiagnosticEntry("ECDH P-256", ecdh.executed, ecdh.ok, ecdh.detail, ecdh.diagnostic),
                    KeyMintDiagnosticEntry("RSA-PSS SHA-256", rsaPss.executed, rsaPss.ok, rsaPss.detail, rsaPss.diagnostic),
                    KeyMintDiagnosticEntry("AES-CBC/CTR auth", aesCbcCtr.executed, aesCbcCtr.ok, aesCbcCtr.detail, aesCbcCtr.diagnostic),
                    KeyMintDiagnosticEntry("AES-CBC padding auth", aesCbcNoPadding.executed, aesCbcNoPadding.ok, aesCbcNoPadding.detail, aesCbcNoPadding.diagnostic),
                    KeyMintDiagnosticEntry("EC SHA-512 auth", ecSha512.executed, ecSha512.ok, ecSha512.detail, ecSha512.diagnostic),
                    KeyMintDiagnosticEntry("RSA-PSS SHA-512 auth", rsaPssSha512.executed, rsaPssSha512.ok, rsaPssSha512.detail, rsaPssSha512.diagnostic),
                    KeyMintDiagnosticEntry("RSA-PSS PKCS#1 auth", rsaPssPkcs1.executed, rsaPssPkcs1.ok, rsaPssPkcs1.detail, rsaPssPkcs1.diagnostic),
                    KeyMintDiagnosticEntry("RSA OAEP/PKCS#1 auth", rsaOaepPkcs1.executed, rsaOaepPkcs1.ok, rsaOaepPkcs1.detail, rsaOaepPkcs1.diagnostic),
                    KeyMintDiagnosticEntry("RSA PKCS#1/OAEP auth", rsaPkcs1Oaep.executed, rsaPkcs1Oaep.ok, rsaPkcs1Oaep.detail, rsaPkcs1Oaep.diagnostic),
                    KeyMintDiagnosticEntry("RSA-OAEP MGF1", rsaOaepMgf1.executed, rsaOaepMgf1.ok, rsaOaepMgf1.detail, rsaOaepMgf1.diagnostic),
                    KeyMintDiagnosticEntry("RSA-OAEP MGF1 auth", rsaOaepMgf1Sha1.executed, rsaOaepMgf1Sha1.ok, rsaOaepMgf1Sha1.detail, rsaOaepMgf1Sha1.diagnostic),
                    KeyMintDiagnosticEntry("RSA-OAEP SHA-256", rsaOaepSha256.executed, rsaOaepSha256.ok, rsaOaepSha256.detail, rsaOaepSha256.diagnostic),
                    KeyMintDiagnosticEntry("RSA-OAEP SHA-1 auth", rsaOaepSha1.executed, rsaOaepSha1.ok, rsaOaepSha1.detail, rsaOaepSha1.diagnostic),
                    KeyMintDiagnosticEntry("EC NONE auth", ecNone.executed, ecNone.ok, ecNone.detail, ecNone.diagnostic),
                    KeyMintDiagnosticEntry("RSA PKCS#1 SHA-1 auth", rsaPkcs1Sha1.executed, rsaPkcs1Sha1.ok, rsaPkcs1Sha1.detail, rsaPkcs1Sha1.diagnostic),
                    KeyMintDiagnosticEntry("RSA PKCS#1/PSS auth", rsaPkcs1Pss.executed, rsaPkcs1Pss.ok, rsaPkcs1Pss.detail, rsaPkcs1Pss.diagnostic),
                    KeyMintDiagnosticEntry("Grant updateSubcomponent", grantUpdateSubcomponent.executed, grantUpdateSubcomponent.ok, grantUpdateSubcomponent.detail, grantUpdateSubcomponent.diagnostic),
                ),
            ),
        )
    }

    private fun grantUpdateSubcomponent(useStrongBox: Boolean): KeyMintCheckResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return KeyMintCheckResult(
                ok = true,
                detail = "Grant updateSubcomponent requires Android 12 or newer.",
                executed = false,
            )
        }
        val keyStore = AndroidKeyStoreTools.loadKeyStore()
        val alias = "duck_grant_update_${System.nanoTime()}"
        val binderClient = Keystore2PrivateBinderClient()
        val grantClient = Keystore2PrivateGrantClient(binderClient)
        val random = java.security.SecureRandom()
        val markerCert = ByteArray(32).also(random::nextBytes)
        val markerChain = ByteArray(32).also(random::nextBytes)
        var grantCreated = false
        return try {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=Duck Grant Update, O=Eltavine",
                useStrongBox = useStrongBox,
            )
            val service = binderClient.getKeystoreService() ?: return KeyMintCheckResult(
                ok = true,
                detail = "Grant updateSubcomponent skipped: Keystore2 service unavailable.",
                executed = false,
            )
            val constants = grantClient.constantsSnapshot()
            val grant = grantClient.grantAliasToUid(
                service = service,
                alias = alias,
                uid = Process.myUid(),
                accessVector = constants.permissionGetInfo or constants.permissionUpdate,
            )
            val grantId = grant.grantId
            if (!grant.available || grantId == null) {
                return KeyMintCheckResult(
                    ok = true,
                    detail = "Grant updateSubcomponent skipped: ${grant.detail}",
                    executed = false,
                )
            }
            grantCreated = true
            val grantDescriptor = grantClient.createGrantDescriptor(grantId)
            val updateFailure = runCatching {
                service.javaClass
                    .getMethod(
                        "updateSubcomponent",
                        grantDescriptor.javaClass,
                        ByteArray::class.java,
                        ByteArray::class.java,
                    )
                    .invoke(service, grantDescriptor, markerCert, markerChain)
            }.exceptionOrNull()
            if (updateFailure != null) {
                return KeyMintCheckResult(
                    ok = false,
                    detail = "Grant updateSubcomponent failed after grant: ${binderClient.describeThrowable(updateFailure)}",
                )
            }
            val response = binderClient.getKeyEntryResponse(service, grantDescriptor)
                ?: return KeyMintCheckResult(false, "Grant updateSubcomponent readback returned no KeyEntryResponse.")
            val appResponse = binderClient.getKeyEntryResponse(service, binderClient.createKeyDescriptor(alias))
                ?: return KeyMintCheckResult(false, "Grant updateSubcomponent APP readback returned no KeyEntryResponse.")
            val certMatches = binderClient.getCertificateBlob(response)?.contentEquals(markerCert) == true
            val chainMatches = binderClient.getCertificateChainBlob(response)?.contentEquals(markerChain) == true
            val appCertMatches = binderClient.getCertificateBlob(appResponse)?.contentEquals(markerCert) == true
            val appChainMatches = binderClient.getCertificateChainBlob(appResponse)?.contentEquals(markerChain) == true
            KeyMintCheckResult(
                ok = certMatches && chainMatches && appCertMatches && appChainMatches,
                detail = "grantUpdateSubcomponent certMatches=$certMatches, chainMatches=$chainMatches, " +
                    "appCertMatches=$appCertMatches, appChainMatches=$appChainMatches.",
            )
        } catch (throwable: Throwable) {
            if (grantCreated) {
                KeyMintCheckResult(false, "Grant updateSubcomponent failed after grant: ${binderClient.describeThrowable(throwable)}")
            } else {
                KeyMintCheckResult(
                    ok = true,
                    detail = "Grant updateSubcomponent skipped: ${binderClient.describeThrowable(throwable)}",
                    executed = false,
                )
            }
        } finally {
            if (grantCreated) {
                runCatching { grantClient.revokeAliasGrant(alias = alias, uid = Process.myUid()) }
            }
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }
}
