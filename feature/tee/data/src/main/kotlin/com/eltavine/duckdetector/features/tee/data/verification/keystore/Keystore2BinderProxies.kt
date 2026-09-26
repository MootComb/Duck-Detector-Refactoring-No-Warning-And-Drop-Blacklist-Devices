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

import android.os.IBinder
import android.os.Parcel
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.Proxy

internal fun createPrivateKeystoreServiceProxy(
    rawBinder: IBinder,
    diagnosticsCollector: CapturedThrowableCollector,
    captureGenerateKeyReplies: Boolean,
): Any? {
    val serviceInterface = loadClass(CLASS_IKEYSTORE_SERVICE)
    val serviceProxyClass = loadClass("${CLASS_IKEYSTORE_SERVICE}\$Stub\$Proxy")
    val constructor = serviceProxyClass.getDeclaredConstructor(IBinder::class.java)
    constructor.isAccessible = true
    val stubProxy = constructor.newInstance(rawBinder)

    return Proxy.newProxyInstance(
        ClassLoader.getSystemClassLoader(),
        arrayOf(serviceInterface),
    ) { _, method, args ->
        invokeProxyMethod(
            target = stubProxy,
            method = method,
            args = args,
            mapper = { result ->
                // service.getSecurityLevel() 返回的对象也必须包一层私有代理；否则 generateKey 这类深层 transact 会绕过会话级诊断和 reply capture。
                // The object returned by service.getSecurityLevel() also needs a private proxy, or deeper transacts such as generateKey bypass session diagnostics and reply capture.
                if (method.name == "getSecurityLevel" && result != null) {
                    createPrivateSecurityLevelProxy(
                        realSecurityLevel = result,
                        diagnosticsCollector = diagnosticsCollector,
                        captureGenerateKeyReplies = captureGenerateKeyReplies,
                    )
                } else {
                    result
                }
            },
            diagnosticsCollector = diagnosticsCollector,
            failurePhase = "service.${method.name}",
        )
    }
}

private fun createPrivateSecurityLevelProxy(
    realSecurityLevel: Any,
    diagnosticsCollector: CapturedThrowableCollector,
    captureGenerateKeyReplies: Boolean,
): Any {
    return runCatching {
        val securityLevelInterface = loadClass(CLASS_IKEYSTORE_SECURITY_LEVEL)
        val securityLevelProxyClass = loadClass("${CLASS_IKEYSTORE_SECURITY_LEVEL}\$Stub\$Proxy")
        val asBinderMethod = realSecurityLevel.javaClass.getMethod("asBinder")
        val rawBinder = asBinderMethod.invoke(realSecurityLevel) as IBinder

        val binderProxy = Proxy.newProxyInstance(
            ClassLoader.getSystemClassLoader(),
            arrayOf(IBinder::class.java),
        ) { _, method, args ->
            when (method.name) {
                "queryLocalInterface" -> null
                "transact" -> {
                    val transactionCode = args[0] as Int
                    val data = args[1] as Parcel
                    val reply = args[2] as? Parcel
                    val success = rawBinder.transact(
                        transactionCode,
                        data,
                        reply,
                        args[3] as Int,
                    )
                    // generateKey 指纹检测依赖原始 reply bytes，所以只能在 transact 边界抓包，晚一步就只剩解包后的对象了。
                    // The generateKey fingerprint depends on raw reply bytes, so capture has to happen at the transact boundary before the parcel is decoded.
                    if (captureGenerateKeyReplies) {
                        captureGenerateKeyReplyFromTransact(
                            transactionCode = transactionCode,
                            data = data,
                            reply = reply,
                            transactReturned = success,
                        )
                    }
                    success
                }
                else -> invokeProxyMethod(
                    rawBinder,
                    method,
                    args,
                    diagnosticsCollector = diagnosticsCollector,
                    failurePhase = "securityLevelBinder.${method.name}",
                )
            }
        } as IBinder

        val constructor = securityLevelProxyClass.getDeclaredConstructor(IBinder::class.java)
        constructor.isAccessible = true
        val stubProxy = constructor.newInstance(binderProxy)
        Proxy.newProxyInstance(
            ClassLoader.getSystemClassLoader(),
            arrayOf(securityLevelInterface),
        ) { _, method, args ->
            if (method.name == "asBinder") {
                binderProxy
            } else {
                invokeProxyMethod(
                    stubProxy,
                    method,
                    args,
                    diagnosticsCollector = diagnosticsCollector,
                    failurePhase = "securityLevel.${method.name}",
                )
            }
        }
    }.getOrElse { realSecurityLevel }
}

internal fun invokeProxyMethod(
    target: Any,
    method: Method,
    args: Array<out Any?>?,
    mapper: ((Any?) -> Any?)? = null,
    diagnosticsCollector: CapturedThrowableCollector? = null,
    failurePhase: String? = null,
): Any? {
    return try {
        val result = method.invoke(target, *(args ?: emptyArray()))
        mapper?.invoke(result) ?: result
    } catch (throwable: InvocationTargetException) {
        val cause = throwable.cause ?: throwable
        if (diagnosticsCollector != null && failurePhase != null) {
            diagnosticsCollector.record(
                phase = failurePhase,
                summary = describeKeystoreThrowable(cause),
                throwable = cause,
            )
        }
        throw cause
    }
}

internal fun captureReplySnapshot(reply: Parcel): Keystore2ReplySnapshot? {
    val rawBytes = runCatching { reply.marshall() }.getOrDefault(ByteArray(0))
    if (rawBytes.isEmpty() && reply.dataSize() == 0) {
        return null
    }
    reply.setDataPosition(0)
    val exceptionCode = if (reply.dataSize() >= 4) reply.readInt() else null
    val secondWord = if (reply.dataSize() >= 8) reply.readInt() else null
    val trailingInts = buildList {
        while (reply.dataPosition() + 4 <= reply.dataSize() && size < 4) {
            add(reply.readInt())
        }
    }
    reply.setDataPosition(0)
    return Keystore2ReplySnapshot(
        rawPrefix = rawReplyPrefix(rawBytes),
        exceptionCode = exceptionCode,
        secondWord = secondWord,
        trailingInts = trailingInts,
        dataSize = rawBytes.size,
    )
}

private fun captureGenerateKeyReplyFromTransact(
    transactionCode: Int,
    data: Parcel,
    reply: Parcel?,
    transactReturned: Boolean,
) {
    val slot = generateKeyReplyCaptureSlot.get() ?: return
    if (transactionCode != generateKeyTransactionCode()) {
        return
    }
    if (slot.completed) {
        return
    }
    slot.transactionCode = transactionCode
    slot.transactReturned = transactReturned
    runCatching { data.marshallPreservingPosition() }
        .onSuccess { rawRequest ->
            if (rawRequest.isNotEmpty() || data.dataSize() > 0) {
                slot.rawRequest = rawRequest
                slot.requestPrefix = rawReplyPrefix(rawRequest)
            }
        }
    if (reply == null) {
        slot.failureReason = "generateKey transact completed without a reply parcel."
        slot.completed = true
        return
    }
    val rawReply = runCatching { reply.marshallPreservingPosition() }.getOrElse { throwable ->
        slot.failureReason = throwable.message ?: "generateKey reply marshalling failed."
        slot.completed = true
        return
    }
    if (rawReply.isEmpty() && reply.dataSize() == 0) {
        slot.failureReason = "generateKey reply parcel was empty."
        slot.completed = true
        return
    }
    slot.rawReply = rawReply
    slot.rawPrefix = rawReplyPrefix(rawReply)
    slot.completed = true
}

private fun Parcel.marshallPreservingPosition(): ByteArray {
    val originalPosition = dataPosition()
    return try {
        marshall()
    } finally {
        setDataPosition(originalPosition)
    }
}

private fun rawReplyPrefix(rawReply: ByteArray): String {
    return rawReply
        .take(MAX_REPLY_PREFIX_BYTES)
        .joinToString(" ") { "%02X".format(it.toInt() and 0xFF) }
}

private fun generateKeyTransactionCode(): Int {
    cachedGenerateKeyTransactionCode?.let { return it }
    val resolved = runCatching {
        val stubClass = loadClass("${CLASS_IKEYSTORE_SECURITY_LEVEL}\$Stub")
        stubClass.getField("TRANSACTION_generateKey").getInt(null)
    }.getOrDefault(Keystore2PrivateBinderClient.TRANSACTION_GENERATE_KEY)
    cachedGenerateKeyTransactionCode = resolved
    return resolved
}

@Volatile
private var cachedGenerateKeyTransactionCode: Int? = null

internal val generateKeyReplyCaptureSlot = ThreadLocal<GenerateKeyReplyCaptureSlot?>()
private const val MAX_REPLY_PREFIX_BYTES = 32
internal const val CLASS_IKEYSTORE_SERVICE = "android.system.keystore2.IKeystoreService"
private const val CLASS_IKEYSTORE_SECURITY_LEVEL = "android.system.keystore2.IKeystoreSecurityLevel"
