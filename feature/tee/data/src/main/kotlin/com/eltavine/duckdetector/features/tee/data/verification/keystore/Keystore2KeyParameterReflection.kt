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

import java.security.SecureRandom

internal fun invokeGenerateKey(
    securityLevel: Any,
    keyDescriptor: Any,
    attestationKeyDescriptor: Any?,
    parameters: List<Any>,
): Any? {
    val invocation = buildGenerateKeyInvocation(
        securityLevel = securityLevel,
        keyDescriptor = keyDescriptor,
        attestationKeyDescriptor = attestationKeyDescriptor,
        parameters = parameters,
    )
    return invokeProxyMethod(invocation.target, invocation.method, invocation.args)
}

internal fun invokeGenerateKeyWithReplyCapture(
    securityLevel: Any,
    keyDescriptor: Any,
    attestationKeyDescriptor: Any?,
    parameters: List<Any>,
): GenerateKeyReplyCaptureSnapshot {
    val invocation = buildGenerateKeyInvocation(
        securityLevel = securityLevel,
        keyDescriptor = keyDescriptor,
        attestationKeyDescriptor = attestationKeyDescriptor,
        parameters = parameters,
    )
    val slot = GenerateKeyReplyCaptureSlot()
    generateKeyReplyCaptureSlot.set(slot)
    return try {
        runCatching {
            invokeProxyMethod(invocation.target, invocation.method, invocation.args)
        }.fold(
            onSuccess = {
                slot.toSnapshot(
                    defaultFailureReason = "generateKey completed without an observable reply payload.",
                )
            },
            onFailure = { throwable ->
                slot.toSnapshot(
                    throwable = throwable,
                    defaultFailureReason = "generateKey failed before the private binder proxy captured a reply.",
                )
            },
        )
    } finally {
        generateKeyReplyCaptureSlot.remove()
    }
}

private fun buildGenerateKeyInvocation(
    securityLevel: Any,
    keyDescriptor: Any,
    attestationKeyDescriptor: Any?,
    parameters: List<Any>,
): HiddenMethodInvocation {
    val keyParameterClass = loadClass(CLASS_KEY_PARAMETER)
    val array = java.lang.reflect.Array.newInstance(keyParameterClass, parameters.size)
    parameters.forEachIndexed { index, value ->
        java.lang.reflect.Array.set(array, index, value)
    }
    val generateKeyMethod = securityLevel.javaClass.methods.firstOrNull {
        it.name == "generateKey" &&
            it.parameterTypes.size == 5 &&
            it.parameterTypes[0].isAssignableFrom(keyDescriptor.javaClass) &&
            it.parameterTypes[1].isAssignableFrom(keyDescriptor.javaClass) &&
            it.parameterTypes[2].isArray &&
            it.parameterTypes[2].componentType?.isAssignableFrom(keyParameterClass) == true &&
            it.parameterTypes[3] == Int::class.javaPrimitiveType &&
            it.parameterTypes[4] == ByteArray::class.java
    } ?: throw NoSuchMethodException("Unable to find hidden generateKey signature on ${securityLevel.javaClass.name}")
    generateKeyMethod.isAccessible = true
    return HiddenMethodInvocation(
        target = securityLevel,
        method = generateKeyMethod,
        args = arrayOf(
            keyDescriptor,
            attestationKeyDescriptor,
            array,
            0,
            ByteArray(0),
        ),
    )
}

internal fun buildSigningKeyParameters(attest: Boolean): List<Any> {
    return buildList {
        add(createKeyParameter(0x10000002, 3))
        add(createKeyParameter(0x30000003, 256))
        add(createKeyParameter(0x1000000A, 1))
        add(createKeyParameter(0x20000001, 2))
        add(createKeyParameter(0x20000005, 4))
        add(createKeyParameter(0x700001F7, true))
        if (attest) {
            add(createKeyParameter(0x900002C4.toInt(), ByteArray(32).also(SecureRandom()::nextBytes)))
        }
    }
}

internal fun buildGenerateModeSigningKeyParameters(): List<Any> {
    return buildList {
        add(createKeyParameter(0x10000002, 3))
        add(createKeyParameter(0x1000000A, 1))
        add(createKeyParameter(0x20000005, 4))
        add(createKeyParameter(0x20000001, 2))
        add(createKeyParameter(0x900002C4.toInt(), ByteArray(32).also(SecureRandom()::nextBytes)))
        add(createKeyParameter(0x700001F7, true))
    }
}

internal fun createKeyParameter(tag: Int, value: Any): Any {
    val parameterClass = loadClass(CLASS_KEY_PARAMETER)
    val parameter = parameterClass.getDeclaredConstructor().newInstance()
    setField(parameter, "tag", tag)

    val valueClass = loadClass(CLASS_KEY_PARAMETER_VALUE)
    val valueObject = createKeyParameterValue(valueClass, tag, value)
    setField(parameter, "value", valueObject)
    return parameter
}

private fun createKeyParameterValue(valueClass: Class<*>, tag: Int, value: Any): Any {
    val valueObject = valueClass.getDeclaredConstructor().newInstance()
    val setterName = keyParameterSetterNameForTag(tag)
    val parameterType = keyParameterParameterType(value)

    try {
        // KeyParameterValue 是 AIDL union，优先按真实 setter + 参数类型写值；只有签名被 OEM 改形时才退到名称匹配。
        // KeyParameterValue is an AIDL union, so we prefer the real setter + parameter type and only fall back to name matching for OEM-shaped signatures.
        val setter = valueClass.getDeclaredMethod(setterName, parameterType)
        setter.isAccessible = true
        setter.invoke(valueObject, value)
    } catch (_: NoSuchMethodException) {
        // Fallback is still constrained to the exact union arm name; we do not reinterpret digest as
        // integer or padding as purpose, because that would fabricate a parameter shape different from
        // AOSP KeyParameterValue.
        // fallback 依旧限制在同名 union arm 内，不允许把 digest 当 integer、把 padding 当 purpose
        // 去乱塞值，否则会伪造出偏离 AOSP KeyParameterValue 语义的参数。
        val setter = valueClass.declaredMethods.firstOrNull {
            it.name == setterName && it.parameterTypes.size == 1
        } ?: throw NoSuchMethodException("Unable to find $setterName on ${valueClass.name}")
        setter.isAccessible = true
        setter.invoke(valueObject, value)
    }

    return valueObject
}

internal fun getKeyParameterIntValue(keyParameter: Any): Int? {
    val value = getFieldValue(keyParameter, "value") ?: return null
    sequenceOf(
        "getKeyPurpose",
        "getAlgorithm",
        "getBlockMode",
        "getPaddingMode",
        "getDigest",
        "getEcCurve",
        "getOrigin",
        "getSecurityLevel",
        "getInteger",
    )
        .forEach { methodName ->
            runCatching {
                val method = value.javaClass.getMethod(methodName)
                method.isAccessible = true
                return method.invoke(value) as? Int
            }
        }
    sequenceOf(
        "keyPurpose",
        "algorithm",
        "blockMode",
        "paddingMode",
        "digest",
        "ecCurve",
        "origin",
        "securityLevel",
        "integer",
    )
        .forEach { fieldName ->
            (getFieldValue(value, fieldName) as? Int)?.let { return it }
        }
    return null
}

internal fun intEnumValue(raw: Any?): Int? {
    raw ?: return null
    return when (raw) {
        is Int -> raw
        is Enum<*> -> raw.ordinal
        else -> runCatching {
            raw.javaClass.getMethod("getNumber").invoke(raw) as? Int
        }.getOrNull() ?: runCatching {
            raw.javaClass.getMethod("getValue").invoke(raw) as? Int
        }.getOrNull()
    }
}

internal const val CLASS_KEY_PARAMETER = "android.hardware.security.keymint.KeyParameter"
private const val CLASS_KEY_PARAMETER_VALUE = "android.hardware.security.keymint.KeyParameterValue"
