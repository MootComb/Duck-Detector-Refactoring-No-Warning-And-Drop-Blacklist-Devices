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
import android.os.IBinder
import android.os.Parcel
import java.lang.reflect.Proxy

/**
 * 通过隐藏 API 打开一个“只对当前探针可见”的 Keystore2 私有代理会话，避免把全局 ServiceManager 状态污染给其他探针。
 * Opens a Keystore2 private proxy session that is scoped to the current probe so other probes keep seeing the real ServiceManager state.
 */
class Keystore2PrivateBinderClient {

    fun lookupBinder(): IBinder? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return null
        }
        ensureHiddenApiAccess()
        return runCatching {
            val serviceManager = loadClass("android.os.ServiceManager")
            val getService = serviceManager.getMethod("getService", String::class.java)
            getService.invoke(null, SERVICE_NAME) as? IBinder
        }.getOrNull()
    }

    fun buildGetKeyEntryRequest(alias: String): Keystore2BinderRequest {
        return Keystore2BinderRequest(
            interfaceDescriptor = INTERFACE_DESCRIPTOR,
            transactionCode = TRANSACTION_GET_KEY_ENTRY,
            alias = alias,
        ) { data ->
            data.writeInterfaceToken(INTERFACE_DESCRIPTOR)
            data.writeInt(1)
            data.writeInt(0)
            data.writeLong(-1L)
            data.writeString(alias)
            data.writeByteArray(null)
        }
    }

    fun executeRequest(
        binder: IBinder,
        request: Keystore2BinderRequest,
    ): BinderTransactionResult {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            request.writeTo(data)
            val success = binder.transact(request.transactionCode, data, reply, 0)
            val snapshot = captureReplySnapshot(reply)
            BinderTransactionResult(
                success = success,
                replySnapshot = snapshot,
                replyFailureReason = if (success) null else "Keystore2 transact() returned false for alias=${request.alias}",
            )
        } catch (throwable: Throwable) {
            BinderTransactionResult(
                success = false,
                throwable = throwable,
                replyFailureReason = throwable.message ?: "Keystore2 transact failed for alias=${request.alias}",
            )
        } finally {
            data.recycle()
            reply.recycle()
        }
    }

    fun transactGetKeyEntry(binder: IBinder, alias: String): BinderTransactionResult {
        return executeRequest(binder, buildGetKeyEntryRequest(alias))
    }

    fun openSession(
        useStrongBox: Boolean = false,
        captureGenerateKeyReplies: Boolean = false,
    ): Keystore2PrivateSessionResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return Keystore2PrivateSessionResult(
                failureReason = "Keystore2 private binder proxy requires Android 12 or newer.",
            )
        }

        ensureHiddenApiAccess()
        val binder = lookupBinder() ?: return Keystore2PrivateSessionResult(
            failureReason = "Keystore2 binder endpoint was not available.",
        )
        // 这里统一收集会话内所有隐藏接口异常，供 timing side-channel 在 skip 时做静态签名判定。
        // Collect every hidden-interface failure for this session so timing side-channel can still classify skip-mode signatures.
        val diagnosticsCollector = CapturedThrowableCollector()
        val service = createPrivateKeystoreServiceProxy(
            rawBinder = binder,
            diagnosticsCollector = diagnosticsCollector,
            captureGenerateKeyReplies = captureGenerateKeyReplies,
        ) ?: return Keystore2PrivateSessionResult(
            failureReason = "Keystore2 service interface was not available after opening the private binder session.",
            capturedFailures = diagnosticsCollector.snapshot(),
        )
        val securityLevel = resolveSecurityLevel(
            service = service,
            level = if (useStrongBox) SECURITY_LEVEL_STRONGBOX else SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        ) ?: return Keystore2PrivateSessionResult(
            failureReason = "Keystore2 security level proxy was not available.",
            capturedFailures = diagnosticsCollector.snapshot(),
        )

        val session = Keystore2PrivateSession(
            binder = binder,
            service = service,
            securityLevel = securityLevel,
            proxyInstalled = true,
            serviceProxyActive = Proxy.isProxyClass(service.javaClass),
            securityLevelProxyActive = Proxy.isProxyClass(securityLevel.javaClass),
            diagnosticsCollector = diagnosticsCollector,
        )
        return if (!session.serviceProxyActive || !session.securityLevelProxyActive) {
            Keystore2PrivateSessionResult(
                failureReason = "Keystore2 private binder proxy did not wrap both service and security-level interfaces.",
                capturedFailures = diagnosticsCollector.snapshot(),
            )
        } else {
            Keystore2PrivateSessionResult(session = session)
        }
    }

    fun closeSession(session: Keystore2PrivateSession) {
        generateKeyReplyCaptureSlot.remove()
    }

    fun createKeyDescriptor(alias: String): Any {
        val descriptorClass = loadClass(CLASS_KEY_DESCRIPTOR)
        val descriptor = descriptorClass.getDeclaredConstructor().newInstance()
        setField(descriptor, "domain", 0)
        setField(descriptor, "nspace", -1L)
        setField(descriptor, "alias", alias)
        setField(descriptor, "blob", null)
        return descriptor
    }

    fun generateAttestationKey(securityLevel: Any, keyDescriptor: Any): Any? {
        var lastFailure: Throwable? = null
        val parameterSets = listOf(
            listOf(
                createKeyParameter(0x10000002, 3),
                createKeyParameter(0x30000003, 256),
                createKeyParameter(0x1000000A, 1),
                createKeyParameter(0x20000001, 7),
                createKeyParameter(0x20000005, 4),
                createKeyParameter(0x700001F7, true),
            ),
            listOf(
                createKeyParameter(0x10000002, 3),
                createKeyParameter(0x30000003, 256),
                createKeyParameter(0x1000000A, 1),
                createKeyParameter(0x20000001, 7),
                createKeyParameter(0x20000005, 0),
                createKeyParameter(0x700001F7, true),
            ),
            listOf(
                createKeyParameter(0x10000002, 3),
                createKeyParameter(0x30000003, 256),
                createKeyParameter(0x1000000A, 1),
                createKeyParameter(0x20000001, 7),
                createKeyParameter(0x700001F7, true),
            ),
        )

        for (parameters in parameterSets) {
            try {
                return invokeGenerateKey(securityLevel, keyDescriptor, null, parameters)
            } catch (throwable: Throwable) {
                lastFailure = throwable
            }
        }

        throw lastFailure ?: IllegalStateException("Unable to provision PURPOSE_ATTEST_KEY test key.")
    }

    fun generateSigningKey(
        securityLevel: Any,
        keyDescriptor: Any,
        attestationKeyDescriptor: Any?,
        attest: Boolean,
    ): Any? {
        val parameters = buildSigningKeyParameters(attest)
        return invokeGenerateKey(securityLevel, keyDescriptor, attestationKeyDescriptor, parameters)
    }

    fun generateRsaOaepKey(
        securityLevel: Any,
        keyDescriptor: Any,
        mgfDigest: Int,
    ): Any? {
        val parameters = listOf(
            createKeyParameter(getTagValue("ALGORITHM") ?: 0x10000002, getAlgorithmValue("RSA") ?: 1),
            createKeyParameter(getTagValue("KEY_SIZE") ?: 0x30000003, 2048),
            createKeyParameter(getTagValue("PURPOSE") ?: 0x20000001, getKeyPurposeValue("DECRYPT") ?: 1),
            createKeyParameter(getTagValue("DIGEST") ?: 0x20000005, getDigestValue("SHA_2_256") ?: 4),
            createKeyParameter(getTagValue("PADDING") ?: 0x20000006, getPaddingModeValue("RSA_OAEP") ?: 2),
            createKeyParameter(getTagValue("RSA_PUBLIC_EXPONENT") ?: 0x500000C8, 65537L),
            createKeyParameter(getTagValue("RSA_OAEP_MGF_DIGEST") ?: 0x200000CB, mgfDigest),
            createKeyParameter(getTagValue("NO_AUTH_REQUIRED") ?: 0x700001F7, true),
        )
        return invokeGenerateKey(securityLevel, keyDescriptor, null, parameters)
    }

    fun captureGenerateKeyReply(useStrongBox: Boolean = false): GenerateKeyReplyCaptureResult {
        val sessionResult = openSession(
            useStrongBox = useStrongBox,
            captureGenerateKeyReplies = true,
        )
        val session = sessionResult.session ?: return GenerateKeyReplyCaptureResult(
            available = false,
            detail = sessionResult.failureReason ?: "Keystore2 private binder proxy session unavailable.",
        )
        val alias = "${DEFAULT_GENERATE_MODE_ALIAS_PREFIX}_${System.nanoTime()}"
        val keyDescriptor = createKeyDescriptor(alias)

        return try {
            val capture = invokeGenerateKeyWithReplyCapture(
                securityLevel = session.securityLevel,
                keyDescriptor = keyDescriptor,
                attestationKeyDescriptor = null,
                parameters = buildGenerateModeSigningKeyParameters(),
            )
            when {
                capture.rawReply != null -> GenerateKeyReplyCaptureResult(
                    available = true,
                    rawRequest = capture.rawRequest,
                    requestPrefix = capture.requestPrefix,
                    rawReply = capture.rawReply,
                    rawPrefix = capture.rawPrefix,
                    detail = buildString {
                        append("Captured generateKey reply via private binder proxy transact")
                        append("; bytes=")
                        append(capture.rawReply.size)
                        capture.rawRequest?.let {
                            append(", requestBytes=")
                            append(it.size)
                        }
                        capture.transactionCode?.let {
                            append(", code=")
                            append(it)
                        }
                        capture.transactReturned?.let {
                            append(", transactReturned=")
                            append(it)
                        }
                        capture.throwable?.let {
                            append(", invocation=")
                            append(describeThrowable(it))
                        }
                    },
                )
                else -> GenerateKeyReplyCaptureResult(
                    available = false,
                    rawRequest = capture.rawRequest,
                    requestPrefix = capture.requestPrefix,
                    detail = capture.failureReason
                        ?: capture.throwable?.let(::describeThrowable)
                        ?: "generateKey reply capture did not observe a marshalled reply.",
                )
            }
        } catch (throwable: Throwable) {
            GenerateKeyReplyCaptureResult(
                available = false,
                detail = describeThrowable(throwable),
            )
        } finally {
            deleteKey(session.service, keyDescriptor)
            closeSession(session)
        }
    }

    fun getKeyEntry(service: Any, keyDescriptor: Any) {
        getKeyEntryResponse(service, keyDescriptor)
    }

    fun getKeyEntryResponse(service: Any, keyDescriptor: Any): Any? {
        return service.javaClass
            .getMethod("getKeyEntry", keyDescriptor.javaClass)
            .invoke(service, keyDescriptor)
    }

    fun getReturnedDescriptor(keyEntryResponse: Any): Any? {
        return getMetadata(keyEntryResponse)?.let { metadata ->
            getFieldValue(metadata, "key")
        } ?: getFieldValue(keyEntryResponse, "key")
    }

    fun resolveFollowUpDescriptor(requestedDescriptor: Any, keyMetadataOrResponse: Any?): Any {
        val returnedDescriptor = keyMetadataOrResponse?.let(::getReturnedDescriptor) ?: return requestedDescriptor
        val returnedNamespace = getDescriptorNamespace(returnedDescriptor)
        val keyIdDomain = getDomainKeyId()
        return when {
            // AOSP 在成功生成后可能把后续操作入口切到 KEY_ID 语义；继续拿原 alias descriptor 调隐藏接口，部分设备会直接打成 KEY_NOT_FOUND。
            // AOSP may switch follow-up operations to KEY_ID semantics after generateKey; reusing the original alias descriptor can trigger KEY_NOT_FOUND on some devices.
            getDescriptorDomain(returnedDescriptor) == keyIdDomain -> returnedDescriptor
            returnedNamespace != null && returnedNamespace >= 0L -> createKeyIdDescriptor(
                nspace = returnedNamespace,
                aliasHint = getDescriptorAlias(requestedDescriptor),
            )
            else -> returnedDescriptor
        }
    }

    fun createKeyIdDescriptor(nspace: Long, aliasHint: String? = null): Any {
        val descriptorClass = loadClass(CLASS_KEY_DESCRIPTOR)
        val descriptor = descriptorClass.getDeclaredConstructor().newInstance()
        setField(descriptor, "domain", getDomainKeyId())
        setField(descriptor, "nspace", nspace)
        setField(descriptor, "alias", aliasHint)
        setField(descriptor, "blob", null)
        return descriptor
    }

    fun getDomainKeyId(): Int {
        return runCatching {
            val domainClass = loadClass("android.system.keystore2.Domain")
            domainClass.getField("KEY_ID").getInt(null)
        }.getOrDefault(DOMAIN_KEY_ID_FALLBACK)
    }

    fun deleteKey(service: Any, keyDescriptor: Any) {
        deleteKeyChecked(service, keyDescriptor)
    }

    fun deleteKeyChecked(service: Any, keyDescriptor: Any): Throwable? {
        return runCatching {
            service.javaClass
                .getMethod("deleteKey", keyDescriptor.javaClass)
                .invoke(service, keyDescriptor)
        }.exceptionOrNull()
    }

    fun listEntries(service: Any): Array<Any?> {
        val method = service.javaClass.methods.firstOrNull {
            it.name == "listEntries" && it.parameterTypes.size >= 2
        } ?: throw NoSuchMethodException("Unable to find hidden listEntries on ${service.javaClass.name}")
        method.isAccessible = true
        return toObjectArray(method.invoke(service, *buildListEntriesArgs(method.parameterTypes)))
    }

    fun listEntriesBatched(service: Any, startPastAlias: String): Array<Any?> {
        val method = service.javaClass.methods.firstOrNull {
            it.name == "listEntriesBatched" && it.parameterTypes.size >= 3
        } ?: throw NoSuchMethodException("Unable to find hidden listEntriesBatched on ${service.javaClass.name}")
        method.isAccessible = true
        return toObjectArray(method.invoke(service, *buildListEntriesArgs(method.parameterTypes, startPastAlias)))
    }

    fun createTimingAliases(prefix: String = DEFAULT_ALIAS_PREFIX): TimingKeyAliases {
        val suffix = System.nanoTime()
        return TimingKeyAliases(
            aliasPrefix = prefix,
            attestedAlias = "${prefix}_Attested_$suffix",
            nonAttestedAlias = "${prefix}_NonAttested_$suffix",
            attestKeyAlias = "${prefix}_AttestKey_$suffix",
        )
    }

    fun createSigningOperationParameters(): List<Any> {
        val purposeTag = getTagValue("PURPOSE") ?: 0x10000001
        val digestTag = getTagValue("DIGEST") ?: 0x20000005
        val signPurpose = getKeyPurposeValue("SIGN") ?: 2
        val sha256Digest = getDigestValue("SHA_2_256") ?: 4
        return listOf(
            createKeyParameter(purposeTag, signPurpose),
            createKeyParameter(digestTag, sha256Digest),
        )
    }

    fun createSigningOperationParametersWithAlgorithm(): List<Any> {
        val algorithmTag = getTagValue("ALGORITHM") ?: 0x10000002
        val ecAlgorithm = getAlgorithmValue("EC") ?: 3
        return createSigningOperationParameters() + createKeyParameter(algorithmTag, ecAlgorithm)
    }

    fun createRsaOaepDecryptOperationParameters(digest: Int, mgfDigest: Int?): List<Any> {
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

    fun createOperation(
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

    fun getOperationHandle(createOperationResponse: Any?): Any? {
        if (createOperationResponse == null) {
            return null
        }
        return getFieldValue(createOperationResponse, "iOperation")
            ?: getFieldValue(createOperationResponse, "operation")
    }

    fun getCertificateBlob(keyEntryResponse: Any): ByteArray? {
        return (getFieldValue(keyEntryResponse, "certificate") as? ByteArray)
            ?: (getMetadata(keyEntryResponse)?.let { getFieldValue(it, "certificate") } as? ByteArray)
    }

    fun getCertificateChainBlob(keyEntryResponse: Any): ByteArray? {
        return (getFieldValue(keyEntryResponse, "certificateChain") as? ByteArray)
            ?: (getMetadata(keyEntryResponse)?.let { getFieldValue(it, "certificateChain") } as? ByteArray)
    }

    fun abortOperation(operation: Any?) {
        if (operation == null) {
            return
        }
        operation.javaClass.getMethod("abort").invoke(operation)
    }

    fun updateOperation(operation: Any, input: ByteArray): Any? {
        return operation.javaClass.getMethod("update", ByteArray::class.java).invoke(operation, input)
    }

    fun updateAadOperation(operation: Any, input: ByteArray): Any? {
        return operation.javaClass.getMethod("updateAad", ByteArray::class.java).invoke(operation, input)
    }

    fun finishOperation(operation: Any, input: ByteArray): ByteArray? {
        val method = operation.javaClass.methods.firstOrNull {
            it.name == "finish" &&
                it.parameterTypes.contentEquals(arrayOf(ByteArray::class.java, ByteArray::class.java))
        } ?: throw NoSuchMethodException("Unable to find hidden finish(byte[], byte[]) on ${operation.javaClass.name}")
        method.isAccessible = true
        return method.invoke(operation, input, null) as? ByteArray
    }

    fun isServiceSpecificException(throwable: Throwable): Boolean = isKeystoreServiceSpecificException(throwable)

    fun extractServiceSpecificErrorCode(throwable: Throwable): Int? = keystoreServiceSpecificErrorCode(throwable)

    fun describeThrowable(throwable: Throwable): String = describeKeystoreThrowable(throwable)

    fun getKeystoreService(): Any? {
        return runCatching {
            val binder = lookupBinder() ?: return null
            val stubClass = loadClass("${CLASS_IKEYSTORE_SERVICE}\$Stub")
            val asInterface = stubClass.getMethod("asInterface", IBinder::class.java)
            asInterface.invoke(null, binder)
        }.getOrNull()
    }

    fun resolveSecurityLevel(service: Any, level: Int): Any? {
        return runCatching {
            val method = service.javaClass.methods.firstOrNull {
                it.name == "getSecurityLevel" && it.parameterTypes.size == 1
            } ?: throw NoSuchMethodException("Unable to find hidden getSecurityLevel(int) on ${service.javaClass.name}")
            method.isAccessible = true
            method.invoke(service, level)
        }.getOrNull()
    }

    fun toObjectArray(value: Any?): Array<Any?> {
        if (value == null || !value.javaClass.isArray) {
            return emptyArray()
        }
        val length = java.lang.reflect.Array.getLength(value)
        return Array(length) { index -> java.lang.reflect.Array.get(value, index) }
    }

    companion object {
        const val SERVICE_NAME = "android.system.keystore2.IKeystoreService/default"
        const val INTERFACE_DESCRIPTOR = "android.system.keystore2.IKeystoreService"
        const val TRANSACTION_GET_KEY_ENTRY = 2
        const val TRANSACTION_GENERATE_KEY = 2
        const val SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
        const val SECURITY_LEVEL_STRONGBOX = 2
        const val DEFAULT_ALIAS_PREFIX = "Budin_Key_DuckTiming"
        const val DEFAULT_GENERATE_MODE_ALIAS_PREFIX = "Budin_Key_DuckGenerateMode"
        const val DOMAIN_KEY_ID_FALLBACK = 4

        private const val CLASS_KEY_DESCRIPTOR = "android.system.keystore2.KeyDescriptor"
    }
}
