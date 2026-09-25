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

package com.eltavine.duckdetector.features.tee.data.repository

internal fun keyMintRuntimeIdentityConsistent(
    attestationVersion: Int?,
    keymasterVersion: Int?,
): Boolean {
    if (attestationVersion == null || keymasterVersion == null) {
        return true
    }
    val attestationIsKeyMint = attestationVersion >= KEYMINT_VERSION_FAMILY_BASE
    val keymasterIsKeyMint = keymasterVersion >= KEYMINT_VERSION_FAMILY_BASE
    if (attestationIsKeyMint != keymasterIsKeyMint) {
        return false
    }
    if (attestationIsKeyMint) {
        return attestationVersion == keymasterVersion
    }
    // keymasterVersion keeps the legacy Keymaster encoding (2, 3, 4, 41).
    // attestationVersion is a separate attestation-record semantic (1, 2, 3, 4);
    // this table is an AOSP-defined cross-field relationship, not linear arithmetic.
    // keymasterVersion 保留旧 Keymaster 编码（2、3、4、41），attestationVersion 是独立的
    // attestation record 语义（1、2、3、4）；这里是 AOSP 定义的跨字段映射，不是线性换算。
    //
    // AOSP references:
    // system/keymaster/include/keymaster/km_openssl/attestation_record.h
    // https://android.googlesource.com/platform/system/keymaster/+/refs/heads/main/include/keymaster/km_openssl/attestation_record.h
    // hardware/interfaces/keymaster/4.0/vts/functional/keymaster_hidl_hal_test.cpp
    // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/keymaster/4.0/vts/functional/keymaster_hidl_hal_test.cpp
    return LEGACY_KEYMASTER_TO_ATTESTATION_VERSION[keymasterVersion] == attestationVersion
}

private const val KEYMINT_VERSION_FAMILY_BASE = 100

private val LEGACY_KEYMASTER_TO_ATTESTATION_VERSION = mapOf(
    2 to 1,
    3 to 2,
    4 to 3,
    41 to 4,
)
