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

internal data class RsaOaepMgf1Capability(
    val supported: Boolean,
    val shouldExecute: Boolean,
    val detail: String,
    val diagnostic: String = "",
)

internal data class AuthorizationSummary(
    val tag: Int,
    val intValue: Int?,
    val securityLevel: Int?,
)

internal enum class KeyMintBackendFamily {
    LEGACY_KEYMASTER,
    KEYMINT,
    UNKNOWN,
    CONFLICT,
}

internal data class KeyMintBackendDecision(
    val family: KeyMintBackendFamily,
    val version: Int?,
    val attestationVersion: Int?,
    val keymasterVersion: Int?,
    val skipDetail: String,
)

internal enum class Mgf1ProbeMode {
    // No operation is attempted when the target backend cannot be identified unambiguously.
    // 无法唯一识别目标 backend 时不发起操作，避免把“没测”伪装成“密码学失败”。
    SKIP,
    // KeyMint 1/2: VTS validates begin/finish behavior but does not require the MGF digest
    // authorization to be echoed in key characteristics.
    // KeyMint 1/2：VTS 验证 begin/finish 行为，但不要求 key characteristics 回显 MGF digest。
    OPERATION_ONLY,
    // KeyMint 3+: VTS additionally requires the exact hardware-enforced MGF digest set.
    // KeyMint 3+：VTS 额外要求精确的、由硬件层强制的 MGF digest 集合。
    CHARACTERISTICS_AND_OPERATION,
}

internal data class Mgf1ProbePlan(
    val mode: Mgf1ProbeMode,
    val detail: String,
)

internal fun resolveMgf1ProbePlan(
    backend: KeyMintBackendDecision,
    securityLevelsConsistent: Boolean,
): Mgf1ProbePlan {
    if (backend.family != KeyMintBackendFamily.KEYMINT) {
        return Mgf1ProbePlan(Mgf1ProbeMode.SKIP, backend.skipDetail)
    }
    if (!securityLevelsConsistent) {
        // IKeystoreSecurityLevel operations are scoped to one selected TEE/StrongBox instance.
        // If attestation and keymaster tiers disagree, running against either instance cannot
        // establish the MGF1 behavior of the identity described by the certificate.
        // IKeystoreSecurityLevel 操作绑定到一个明确的 TEE/StrongBox 实例。若 attestation 与
        // keymaster tier 冲突，无论选择哪个实例，都不能证明证书所描述身份的 MGF1 行为。
        return Mgf1ProbePlan(
            Mgf1ProbeMode.SKIP,
            "RSA-OAEP MGF1 skipped because attestation and keymaster security levels disagree.",
        )
    }
    val version = backend.version ?: return Mgf1ProbePlan(
        Mgf1ProbeMode.SKIP,
        "RSA-OAEP MGF1 skipped because the native KeyMint version was unavailable.",
    )
    // AOSP references for the version split and exact characteristics expectation:
    // hardware/interfaces/security/keymint/aidl/vts/functional/KeyMintTest.cpp
    // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/vts/functional/KeyMintTest.cpp
    // hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl
    // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl
    return if (version < KEYMINT_VERSION_3) {
        Mgf1ProbePlan(
            Mgf1ProbeMode.OPERATION_ONLY,
            "KeyMint 1/2 uses raw keystore2 operation checks.",
        )
    } else {
        Mgf1ProbePlan(
            Mgf1ProbeMode.CHARACTERISTICS_AND_OPERATION,
            "KeyMint 3+ requires exact MGF1 characteristics and raw operation checks.",
        )
    }
}

internal fun classifyKeyMintBackend(
    attestationVersion: Int?,
    keymasterVersion: Int?,
    declaredKeyMintVersion: Int?,
    legacyKeymasterDeclared: Boolean,
    runtimeIdentityConsistent: Boolean,
): KeyMintBackendDecision {
    // The 100-based values are native KeyMint attestation encodings. Legacy values use a
    // different Keymaster family, and VINTF is only a declaration fallback. Conflicting signals
    // therefore produce CONFLICT/SKIP instead of choosing whichever value is numerically larger.
    // 100-based 数值属于原生 KeyMint attestation 编码；legacy 数值属于另一套 Keymaster 家族，
    // VINTF 也只是声明兜底。信号冲突时必须 CONFLICT/SKIP，不能随意取数值更大的那个。
    val actualVersions = listOfNotNull(attestationVersion, keymasterVersion)
    val nativeVersions = actualVersions.filter { it >= KEYMINT_VERSION_1 }
    val legacyVersions = actualVersions.filter { it in 0 until KEYMINT_VERSION_1 }
    val hasIdentityConflict = !runtimeIdentityConsistent ||
        (nativeVersions.isNotEmpty() && legacyVersions.isNotEmpty()) ||
        (declaredKeyMintVersion != null && legacyVersions.isNotEmpty()) ||
        (legacyKeymasterDeclared && nativeVersions.isNotEmpty())
    if (hasIdentityConflict) {
        return KeyMintBackendDecision(
            family = KeyMintBackendFamily.CONFLICT,
            version = nativeVersions.maxOrNull() ?: declaredKeyMintVersion,
            attestationVersion = attestationVersion,
            keymasterVersion = keymasterVersion,
            skipDetail = "RSA-OAEP MGF1 skipped because runtime identity signals conflict.",
        )
    }
    if (nativeVersions.isNotEmpty() || declaredKeyMintVersion != null) {
        return KeyMintBackendDecision(
            family = KeyMintBackendFamily.KEYMINT,
            // VINTF is a declaration, not the observed implementation version. Prefer the
            // attested/keymaster value whenever one exists; use VINTF only as a family/version
            // fallback when the runtime did not expose any version at all.
            // VINTF 是声明，不是实际运行时版本。只要运行时有版本，就优先使用 attestation/
            // keymaster 的真实值；只有完全没有运行时版本时才使用 VINTF 作为兜底。
            version = nativeVersions.maxOrNull() ?: declaredKeyMintVersion,
            attestationVersion = attestationVersion,
            keymasterVersion = keymasterVersion,
            skipDetail = "",
        )
    }
    if (legacyVersions.isNotEmpty() || legacyKeymasterDeclared) {
        return KeyMintBackendDecision(
            family = KeyMintBackendFamily.LEGACY_KEYMASTER,
            version = null,
            attestationVersion = attestationVersion,
            keymasterVersion = keymasterVersion,
            skipDetail = "RSA-OAEP MGF1 skipped for legacy Keymaster/km_compat.",
        )
    }
    return KeyMintBackendDecision(
        family = KeyMintBackendFamily.UNKNOWN,
        version = null,
        attestationVersion = attestationVersion,
        keymasterVersion = keymasterVersion,
        skipDetail = "RSA-OAEP MGF1 skipped because the backend family could not be established.",
    )
}

internal fun evaluateRsaOaepMgf1Capability(
    authorizations: List<AuthorizationSummary>,
    attestationVersion: Int?,
    keymasterVersion: Int?,
    declaredKeyMintVersion: Int? = null,
    expectedSecurityLevel: Int = KEYMINT_SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    returnedSecurityLevel: Int = expectedSecurityLevel,
    probeMode: Mgf1ProbeMode? = null,
): RsaOaepMgf1Capability {
    // KeyMint 3+ tightened the contract: the allowed MGF digests must be surfaced back through
    // hardware-enforced key characteristics, and VTS compares the exact set.
    // KeyMint 1/2 does not have that characteristics contract, so we switch to runtime operation tests.
    // KeyMint 3+ 必须在硬件强制的 key characteristics 中回显允许的 MGF digest 集合，VTS 会比对
    // 精确集合；而 KeyMint 1/2 没有这个 contract，所以我们退回到运行时 begin/finish 语义检测。
    //
    // AOSP references:
    // hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl
    // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl
    // hardware/interfaces/security/keymint/aidl/vts/functional/KeyMintTest.cpp
    // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/vts/functional/KeyMintTest.cpp
    val diagnostic = buildString {
        append("observedKeyMintVersion=")
        append(deriveObservedKeyMintVersion(attestationVersion, keymasterVersion, declaredKeyMintVersion) ?: "null")
        append(", expectedSecurityLevel=")
        append(expectedSecurityLevel)
        append(", returnedSecurityLevel=")
        append(returnedSecurityLevel)
        append(", authorizations=")
        append(
            authorizations.joinToString { authorization ->
                "tag=0x${authorization.tag.toUInt().toString(16)}," +
                    "value=${authorization.intValue ?: "null"}," +
                    "securityLevel=${authorization.securityLevel ?: "null"}"
            }.ifBlank { "none" },
        )
    }
    val keyMintVersion = deriveObservedKeyMintVersion(
        attestationVersion,
        keymasterVersion,
        declaredKeyMintVersion,
    )
    val validationMode = probeMode ?: when {
        keyMintVersion == null || keyMintVersion < KEYMINT_VERSION_1 -> Mgf1ProbeMode.SKIP
        keyMintVersion < KEYMINT_VERSION_3 -> Mgf1ProbeMode.OPERATION_ONLY
        else -> Mgf1ProbeMode.CHARACTERISTICS_AND_OPERATION
    }
    if (validationMode == Mgf1ProbeMode.SKIP) {
        return RsaOaepMgf1Capability(
            supported = false,
            shouldExecute = false,
            detail = "RSA-OAEP MGF1 skipped for legacy Keymaster/km_compat.",
            diagnostic = diagnostic,
        )
    }
    if (returnedSecurityLevel != expectedSecurityLevel) {
        return RsaOaepMgf1Capability(
            supported = false,
            shouldExecute = true,
            detail = "Generated key security level=$returnedSecurityLevel; expected=$expectedSecurityLevel.",
            diagnostic = diagnostic,
        )
    }
    if (validationMode == Mgf1ProbeMode.OPERATION_ONLY) {
        return RsaOaepMgf1Capability(
            supported = true,
            shouldExecute = true,
            detail = "KeyMint 1/2 uses raw keystore2 operation checks; characteristics are not required by VTS.",
            diagnostic = diagnostic,
        )
    }
    val mgfAuthorizations = authorizations.filter { it.tag == KEYMINT_TAG_RSA_OAEP_MGF_DIGEST }
    if (mgfAuthorizations.isEmpty()) {
        return RsaOaepMgf1Capability(
            supported = false,
            shouldExecute = true,
            detail = "Generated key characteristics omit RSA_OAEP_MGF_DIGEST on KeyMint 3+.",
            diagnostic = diagnostic,
        )
    }
    val wrongSecurityLevel = mgfAuthorizations.any { it.securityLevel != expectedSecurityLevel }
    if (wrongSecurityLevel) {
        return RsaOaepMgf1Capability(
            supported = false,
            shouldExecute = true,
            detail = "RSA_OAEP_MGF_DIGEST was not enforced by the selected hardware security level.",
            diagnostic = diagnostic,
        )
    }
    val observedDigests = mgfAuthorizations.mapNotNull { it.intValue }
    if (observedDigests != listOf(KEYMINT_DIGEST_SHA_256) || mgfAuthorizations.any { it.intValue == null }) {
        return RsaOaepMgf1Capability(
            supported = false,
            shouldExecute = true,
            detail = "Generated key characteristics expose MGF1 digests=$observedDigests; expected=[${KEYMINT_DIGEST_SHA_256}].",
            diagnostic = diagnostic,
        )
    }
    return RsaOaepMgf1Capability(
        supported = true,
        shouldExecute = true,
        detail = "Generated key characteristics exactly match hardware-enforced MGF1 SHA-256.",
        diagnostic = diagnostic,
    )
}

internal fun isKeyMintOneOrTwo(
    attestationVersion: Int?,
    keymasterVersion: Int?,
    declaredKeyMintVersion: Int? = null,
): Boolean {
    return deriveObservedKeyMintVersion(
        attestationVersion,
        keymasterVersion,
        declaredKeyMintVersion,
    ) in 100..299
}

internal data class MgfRejectionCase(
    val name: String,
    val mgfDigest: Int?,
    val expectedErrorCodes: Set<Int>,
)

internal fun keyMintMgfRejectionCases(): List<MgfRejectionCase> {
    val incompatibleOrUnsupported = setOf(
        KEYMINT_ERROR_INCOMPATIBLE_MGF_DIGEST,
        KEYMINT_ERROR_UNSUPPORTED_MGF_DIGEST,
    )
    return listOf(
        MgfRejectionCase("default-sha1", null, incompatibleOrUnsupported),
        MgfRejectionCase(
            "explicit-sha224",
            KEYMINT_DIGEST_SHA_224,
            setOf(KEYMINT_ERROR_INCOMPATIBLE_MGF_DIGEST),
        ),
        MgfRejectionCase(
            "unsupported-none",
            KEYMINT_DIGEST_NONE,
            setOf(KEYMINT_ERROR_UNSUPPORTED_MGF_DIGEST),
        ),
    )
}

internal fun deriveObservedKeyMintVersion(
    attestationVersion: Int?,
    keymasterVersion: Int?,
    declaredKeyMintVersion: Int? = null,
): Int? {
    // Runtime attestation/keymaster values describe the selected backend. VINTF is only a
    // fallback when both runtime values are absent; it must not upgrade a real KeyMint 2
    // implementation into a stricter KeyMint 3 path just because the declaration is newer.
    // 运行时 attestation/keymaster 值描述当前选中的 backend。只有两个运行时值都缺失时才用
    // VINTF 兜底；不能因为声明较新，就把真实 KeyMint 2 升级到更严格的 KeyMint 3 路径。
    return listOfNotNull(attestationVersion, keymasterVersion)
        .firstOrNull { it >= KEYMINT_VERSION_1 }
        ?: declaredKeyMintVersion?.takeIf { it >= KEYMINT_VERSION_1 }
}

private const val KEYMINT_DIGEST_NONE = 0

private const val KEYMINT_VERSION_1 = 100

private const val KEYMINT_VERSION_3 = 300

internal const val KEYMINT_DIGEST_SHA_256 = 4

private const val KEYMINT_DIGEST_SHA_224 = 3

private const val KEYMINT_ERROR_INCOMPATIBLE_MGF_DIGEST = -78

private const val KEYMINT_ERROR_UNSUPPORTED_MGF_DIGEST = -79

private const val KEYMINT_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1

private const val KEYMINT_SECURITY_LEVEL_STRONGBOX = 2
