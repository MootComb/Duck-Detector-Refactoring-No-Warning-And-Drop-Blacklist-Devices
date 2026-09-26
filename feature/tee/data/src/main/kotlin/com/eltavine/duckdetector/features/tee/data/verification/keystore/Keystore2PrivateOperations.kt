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

internal fun Keystore2PrivateBinderClient.createSigningOperationParameters(): List<Any> {
    val purposeTag = getTagValue("PURPOSE") ?: 0x10000001
    val digestTag = getTagValue("DIGEST") ?: 0x20000005
    val signPurpose = getKeyPurposeValue("SIGN") ?: 2
    val sha256Digest = getDigestValue("SHA_2_256") ?: 4
    return listOf(
        createKeyParameter(purposeTag, signPurpose),
        createKeyParameter(digestTag, sha256Digest),
    )
}

internal fun Keystore2PrivateBinderClient.createSigningOperationParametersWithAlgorithm(): List<Any> {
    val algorithmTag = getTagValue("ALGORITHM") ?: 0x10000002
    val ecAlgorithm = getAlgorithmValue("EC") ?: 3
    return createSigningOperationParameters() + createKeyParameter(algorithmTag, ecAlgorithm)
}

internal fun Keystore2PrivateBinderClient.createRsaOaepDecryptOperationParameters(digest: Int, mgfDigest: Int?): List<Any> {
    val purposeTag = getTagValue("PURPOSE") ?: 0x20000001
    val digestTag = getTagValue("DIGEST") ?: 0x20000005
    val paddingTag = getTagValue("PADDING") ?: 0x20000006
    val mgfDigestTag = getTagValue("RSA_OAEP_MGF_DIGEST") ?: 0x200000CB
    val decryptPurpose = getKeyPurposeValue("DECRYPT") ?: 1
    val rsaOaepPadding = getPaddingModeValue("RSA_OAEP") ?: 2
    return buildList {
        add(createKeyParameter(purposeTag, decryptPurpose))
        add(createKeyParameter(digestTag, digest))
        add(createKeyParameter(paddingTag, rsaOaepPadding))
        mgfDigest?.let { add(createKeyParameter(mgfDigestTag, it)) }
    }
}

internal fun Keystore2PrivateBinderClient.createOperation(
    securityLevel: Any,
    keyDescriptor: Any,
    parameters: List<Any>,
): Any? {
    // Hidden binder signatures vary less than OEM wrapper classes do, so we insist on the exact
    // createOperation(KeyDescriptor, KeyParameter[], boolean) shape and fail closed otherwise.
    // 这里故意要求精确签名，而不是模糊匹配任意 createOperation 重载；一旦签名不对，就说明我们
    // 已经不在验证 AOSP 语义，而是在猜 OEM 私有包装，必须 fail closed。
    //
    // AOSP reference:
    // system/hardware/interfaces/keystore2/aidl/android/system/keystore2/IKeystoreSecurityLevel.aidl
    // https://android.googlesource.com/platform/system/hardware/interfaces/+/refs/heads/main/keystore2/aidl/android/system/keystore2/IKeystoreSecurityLevel.aidl
    val keyParameterClass = loadClass(CLASS_KEY_PARAMETER)
    val array = java.lang.reflect.Array.newInstance(keyParameterClass, parameters.size)
    parameters.forEachIndexed { index, value ->
        java.lang.reflect.Array.set(array, index, value)
    }
    securityLevel.javaClass.methods.firstOrNull {
        it.name == "createOperation" &&
            it.parameterTypes.size == 3 &&
            it.parameterTypes[0].isAssignableFrom(keyDescriptor.javaClass) &&
            it.parameterTypes[1].isArray &&
            it.parameterTypes[1].componentType?.isAssignableFrom(keyParameterClass) == true &&
            (it.parameterTypes[2] == Boolean::class.javaPrimitiveType ||
                it.parameterTypes[2] == Boolean::class.java)
    }?.let { exactMethod ->
        exactMethod.isAccessible = true
        return exactMethod.invoke(securityLevel, keyDescriptor, array, false)
    }
    throw NoSuchMethodException("Unable to find exact hidden createOperation signature on ${securityLevel.javaClass.name}")
}

internal fun Keystore2PrivateBinderClient.getOperationHandle(createOperationResponse: Any?): Any? {
    if (createOperationResponse == null) {
        return null
    }
    return getFieldValue(createOperationResponse, "iOperation")
        ?: getFieldValue(createOperationResponse, "operation")
}

internal fun Keystore2PrivateBinderClient.abortOperation(operation: Any?) {
    if (operation == null) {
        return
    }
    operation.javaClass.getMethod("abort").invoke(operation)
}

internal fun Keystore2PrivateBinderClient.updateOperation(operation: Any, input: ByteArray): Any? {
    return operation.javaClass.getMethod("update", ByteArray::class.java).invoke(operation, input)
}

internal fun Keystore2PrivateBinderClient.updateAadOperation(operation: Any, input: ByteArray): Any? {
    return operation.javaClass.getMethod("updateAad", ByteArray::class.java).invoke(operation, input)
}

internal fun Keystore2PrivateBinderClient.finishOperation(operation: Any, input: ByteArray): ByteArray? {
    val method = operation.javaClass.methods.firstOrNull {
        it.name == "finish" &&
            it.parameterTypes.contentEquals(arrayOf(ByteArray::class.java, ByteArray::class.java))
    } ?: throw NoSuchMethodException("Unable to find hidden finish(byte[], byte[]) on ${operation.javaClass.name}")
    method.isAccessible = true
    return method.invoke(operation, input, null) as? ByteArray
}
