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

fun Keystore2PrivateBinderClient.getMetadata(keyEntryResponse: Any): Any? = getFieldValue(keyEntryResponse, "metadata")

fun Keystore2PrivateBinderClient.getSecurityLevelBinder(keyEntryResponse: Any): Any? = getFieldValue(keyEntryResponse, "iSecurityLevel")

fun Keystore2PrivateBinderClient.getMetadataSecurityLevel(keyEntryResponse: Any): Any? {
    val metadata = getMetadata(keyEntryResponse) ?: return null
    return getFieldValue(metadata, "keySecurityLevel")
}

fun Keystore2PrivateBinderClient.getKeyMetadataSecurityLevel(keyMetadataOrResponse: Any): Int? {
    val metadata = getMetadata(keyMetadataOrResponse) ?: keyMetadataOrResponse
    return intEnumValue(getFieldValue(metadata, "keySecurityLevel"))
}

fun Keystore2PrivateBinderClient.getPureCertSecurityLevel(keyEntryResponse: Any): Any? {
    getSecurityLevelBinder(keyEntryResponse)?.let { return it }
    return getMetadataSecurityLevel(keyEntryResponse)
}

fun Keystore2PrivateBinderClient.getMetadataModificationTimeMs(metadata: Any): Long? {
    val raw = getFieldValue(metadata, "modificationTimeMs") ?: return null
    return when (raw) {
        is Long -> raw
        is Int -> raw.toLong()
        else -> null
    }
}

fun Keystore2PrivateBinderClient.getMetadataAuthorizations(metadata: Any): Array<Any?> {
    return toObjectArray(getFieldValue(metadata, "authorizations"))
}

fun Keystore2PrivateBinderClient.getAuthorizationTag(authorization: Any): Int? {
    val keyParameter = getFieldValue(authorization, "keyParameter") ?: return null
    return getFieldValue(keyParameter, "tag") as? Int
}

fun Keystore2PrivateBinderClient.getAuthorizationSecurityLevel(authorization: Any): Int? {
    return intEnumValue(getFieldValue(authorization, "securityLevel"))
}

fun Keystore2PrivateBinderClient.getAuthorizationIntValue(authorization: Any): Int? {
    val keyParameter = getFieldValue(authorization, "keyParameter") ?: return null
    return getKeyParameterIntValue(keyParameter)
}

fun Keystore2PrivateBinderClient.getAuthorizationDigestValue(authorization: Any): Int? {
    val keyParameter = getFieldValue(authorization, "keyParameter") ?: return null
    val value = getFieldValue(keyParameter, "value") ?: return null
    return runCatching {
        val method = value.javaClass.getMethod("getDigest")
        method.isAccessible = true
        method.invoke(value) as? Int
    }.getOrNull()
}

fun Keystore2PrivateBinderClient.getKeyOriginValue(name: String): Int? {
    return runCatching {
        val originClass = loadClass("android.hardware.security.keymint.KeyOrigin")
        originClass.getField(name).getInt(null)
    }.getOrNull()
}

fun Keystore2PrivateBinderClient.getDescriptorDomain(descriptor: Any): Int? = getFieldValue(descriptor, "domain") as? Int

fun Keystore2PrivateBinderClient.getDescriptorAlias(descriptor: Any): String? = getFieldValue(descriptor, "alias") as? String

fun Keystore2PrivateBinderClient.getDescriptorNamespace(descriptor: Any): Long? {
    val raw = getFieldValue(descriptor, "nspace") ?: return null
    return when (raw) {
        is Long -> raw
        is Int -> raw.toLong()
        else -> null
    }
}

fun Keystore2PrivateBinderClient.getTagValue(name: String): Int? {
    return runCatching {
        val tagClass = loadClass("android.hardware.security.keymint.Tag")
        tagClass.getField(name).getInt(null)
    }.getOrNull()
}

fun Keystore2PrivateBinderClient.getKeyPurposeValue(name: String): Int? {
    return runCatching {
        val purposeClass = loadClass("android.hardware.security.keymint.KeyPurpose")
        purposeClass.getField(name).getInt(null)
    }.getOrNull()
}

fun Keystore2PrivateBinderClient.getDigestValue(name: String): Int? {
    return runCatching {
        val digestClass = loadClass("android.hardware.security.keymint.Digest")
        digestClass.getField(name).getInt(null)
    }.getOrNull()
}

fun Keystore2PrivateBinderClient.getPaddingModeValue(name: String): Int? {
    return runCatching {
        val paddingClass = loadClass("android.hardware.security.keymint.PaddingMode")
        paddingClass.getField(name).getInt(null)
    }.getOrNull()
}

fun Keystore2PrivateBinderClient.getAlgorithmValue(name: String): Int? {
    return runCatching {
        val algorithmClass = loadClass("android.hardware.security.keymint.Algorithm")
        algorithmClass.getField(name).getInt(null)
    }.getOrNull()
}

fun Keystore2PrivateBinderClient.getKeyMintErrorCodeValue(name: String): Int? {
    return runCatching {
        val errorCodeClass = loadClass("android.hardware.security.keymint.ErrorCode")
        errorCodeClass.getField(name).getInt(null)
    }.getOrNull()
}
