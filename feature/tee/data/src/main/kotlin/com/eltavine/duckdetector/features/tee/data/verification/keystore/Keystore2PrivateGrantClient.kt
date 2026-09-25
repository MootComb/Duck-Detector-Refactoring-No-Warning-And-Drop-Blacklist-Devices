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
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GrantReflection.describeThrowable
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GrantReflection.ensureHiddenApiAccess
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GrantReflection.extractServiceSpecificErrorCode
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GrantReflection.findRootCause
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GrantReflection.loadClass
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GrantReflection.readByteArrayField
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GrantReflection.readFieldValue
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GrantReflection.readLongField
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GrantReflection.setField

class Keystore2PrivateGrantClient(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
) {

    fun lookupBinder(): IBinder? = binderClient.lookupBinder()

    fun constantsSnapshot(): Keystore2PrivateGrantConstants {
        return resolveConstants()
    }

    fun createGrantDescriptor(grantId: Long): Any {
        return createDescriptor(grantId, resolveConstants().domainGrant)
    }

    fun grantAliasToUid(alias: String, uid: Int): Keystore2PrivateGrantResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return Keystore2PrivateGrantResult.unavailable(
                phase = Keystore2PrivateGrantPhase.PRIVATE_GRANT,
                detail = "private grant failed: Keystore2 private binder grant requires Android 12 or newer.",
            )
        }
        return withService(
            failurePhase = Keystore2PrivateGrantPhase.PRIVATE_GRANT,
            failurePrefix = "private grant failed",
        ) { service, constants ->
            grantAliasToUid(service, alias, uid, constants)
        }
    }

    fun grantAliasToUid(service: Any, alias: String, uid: Int): Keystore2PrivateGrantResult {
        return runCatching {
            val constants = resolveConstants()
            grantAliasToUid(
                service = service,
                alias = alias,
                uid = uid,
                accessVector = constants.grantAccessVector,
                constants = constants,
            )
        }.getOrElse { throwable ->
            grantFailureResult(
                phase = Keystore2PrivateGrantPhase.PRIVATE_GRANT,
                detail = "private grant failed: ${describeThrowable(throwable)}",
                errorKind = classifyFailure(throwable),
                throwable = throwable,
            )
        }
    }

    fun grantAliasToUid(
        service: Any,
        alias: String,
        uid: Int,
        accessVector: Int,
    ): Keystore2PrivateGrantResult {
        return runCatching {
            val constants = resolveConstants()
            grantAliasToUid(service, alias, uid, accessVector, constants)
        }.getOrElse { throwable ->
            grantFailureResult(
                phase = Keystore2PrivateGrantPhase.PRIVATE_GRANT,
                detail = "private grant failed: ${describeThrowable(throwable)}",
                errorKind = classifyFailure(throwable),
                throwable = throwable,
            )
        }
    }

    fun revokeAliasGrant(alias: String, uid: Int): Keystore2PrivateGrantResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return Keystore2PrivateGrantResult.unavailable(
                phase = Keystore2PrivateGrantPhase.PRIVATE_UNGRANT,
                detail = "private ungrant failed: Keystore2 private binder grant requires Android 12 or newer.",
            )
        }
        return withService(
            failurePhase = Keystore2PrivateGrantPhase.PRIVATE_UNGRANT,
            failurePrefix = "private ungrant failed",
        ) { service, constants ->
            revokeAliasGrant(service, alias, uid, constants)
        }
    }

    fun revokeAliasGrant(service: Any, alias: String, uid: Int): Keystore2PrivateGrantResult {
        return runCatching {
            revokeAliasGrant(service, alias, uid, resolveConstants())
        }.getOrElse { throwable ->
            grantFailureResult(
                phase = Keystore2PrivateGrantPhase.PRIVATE_UNGRANT,
                detail = "private ungrant failed: ${describeThrowable(throwable)}",
                errorKind = classifyFailure(throwable),
                throwable = throwable,
            )
        }
    }

    fun readOwnerChain(alias: String): Keystore2PrivateGrantChainResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return Keystore2PrivateGrantChainResult.unavailable(
                phase = Keystore2PrivateGrantPhase.PRIVATE_GET_KEY_ENTRY_APP,
                detail = "private getKeyEntry(APP) failed: Keystore2 private binder grant requires Android 12 or newer.",
            )
        }
        return withService(
            failurePhase = Keystore2PrivateGrantPhase.PRIVATE_GET_KEY_ENTRY_APP,
            failurePrefix = "private getKeyEntry(APP) failed",
        ) { service, constants ->
            readOwnerChain(service, alias, constants)
        }
    }

    fun readOwnerChain(service: Any, alias: String): Keystore2PrivateGrantChainResult {
        return runCatching {
            readOwnerChain(service, alias, resolveConstants())
        }.getOrElse { throwable ->
            grantFailureResult(
                phase = Keystore2PrivateGrantPhase.PRIVATE_GET_KEY_ENTRY_APP,
                detail = "private getKeyEntry(APP) failed: ${describeThrowable(throwable)}",
                errorKind = classifyFailure(throwable),
                throwable = throwable,
            )
        }
    }

    fun readGrantChain(grantId: Long): Keystore2PrivateGrantChainResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return Keystore2PrivateGrantChainResult.unavailable(
                phase = Keystore2PrivateGrantPhase.PRIVATE_GET_KEY_ENTRY_GRANT,
                detail = "private getKeyEntry(GRANT) failed: Keystore2 private binder grant requires Android 12 or newer.",
            )
        }
        return withService(
            failurePhase = Keystore2PrivateGrantPhase.PRIVATE_GET_KEY_ENTRY_GRANT,
            failurePrefix = "private getKeyEntry(GRANT) failed",
        ) { service, constants ->
            readGrantChain(service, grantId, constants)
        }
    }

    fun readGrantChain(service: Any, grantId: Long): Keystore2PrivateGrantChainResult {
        return runCatching {
            readGrantChain(service, grantId, resolveConstants())
        }.getOrElse { throwable ->
            grantFailureResult(
                phase = Keystore2PrivateGrantPhase.PRIVATE_GET_KEY_ENTRY_GRANT,
                detail = "private getKeyEntry(GRANT) failed: ${describeThrowable(throwable)}",
                errorKind = classifyFailure(throwable),
                throwable = throwable,
            )
        }
    }

    fun readGrantEntry(service: Any, grantId: Long): Keystore2PrivateGrantResult {
        return runCatching {
            val constants = resolveConstants()
            val descriptor = createDescriptor(grantId, constants.domainGrant)
            service.javaClass
                .getMethod("getKeyEntry", descriptor.javaClass)
                .also { it.isAccessible = true }
                .invoke(service, descriptor)
                ?: return@runCatching Keystore2PrivateGrantResult.unavailable(
                    phase = Keystore2PrivateGrantPhase.PRIVATE_OWNER_REPLAY_GRANT,
                    detail = "private owner replay getKeyEntry(GRANT) returned no KeyEntryResponse.",
                )
            Keystore2PrivateGrantResult(
                available = true,
                phase = Keystore2PrivateGrantPhase.PRIVATE_OWNER_REPLAY_GRANT,
                detail = "private owner replay getKeyEntry(GRANT) returned a response.",
            )
        }.getOrElse { throwable ->
            Keystore2PrivateGrantResult.unavailable(
                phase = Keystore2PrivateGrantPhase.PRIVATE_OWNER_REPLAY_GRANT,
                errorKind = classifyFailure(throwable),
                detail = "private owner replay getKeyEntry(GRANT) failed: ${describeThrowable(throwable)}",
                throwable = throwable,
            )
        }
    }

    fun readGrantChain(
        binder: IBinder,
        grantId: Long,
    ): Keystore2PrivateGrantChainResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return Keystore2PrivateGrantChainResult.unavailable(
                phase = Keystore2PrivateGrantPhase.ISOLATED_BINDER_READBACK,
                detail = "isolated binder call blocked: Keystore2 private binder grant requires Android 12 or newer.",
            )
        }
        return withService(
            binder = binder,
            failurePhase = Keystore2PrivateGrantPhase.ISOLATED_BINDER_READBACK,
            failurePrefix = "isolated binder call blocked",
        ) { service, constants ->
            readChainFromDescriptor(
                service = service,
                descriptor = createDescriptor(grantId, constants.domainGrant),
                phase = Keystore2PrivateGrantPhase.ISOLATED_BINDER_READBACK,
                emptyDetail = "isolated binder call blocked: Domain.GRANT certificate chain was empty.",
                successDetailPrefix = "isolated private getKeyEntry(GRANT)",
            )
        }
    }

    private fun <T> withService(
        failurePhase: Keystore2PrivateGrantPhase,
        failurePrefix: String,
        block: (Any, Keystore2PrivateGrantConstants) -> T,
    ): T where T : Keystore2PrivateGrantFailureResult {
        return try {
            val binder = lookupBinder() ?: return grantFailureResult(
                phase = failurePhase,
                detail = "$failurePrefix: private keystore2 binder unavailable.",
            )
            withService(binder, failurePhase, failurePrefix, block)
        } catch (throwable: Throwable) {
            grantFailureResult(
                phase = failurePhase,
                detail = "$failurePrefix: ${describeThrowable(throwable)}",
                errorKind = classifyFailure(throwable),
                throwable = throwable,
            )
        }
    }

    private fun <T> withService(
        binder: IBinder,
        failurePhase: Keystore2PrivateGrantPhase,
        failurePrefix: String,
        block: (Any, Keystore2PrivateGrantConstants) -> T,
    ): T where T : Keystore2PrivateGrantFailureResult {
        ensureHiddenApiAccess()
        return try {
            val service = createKeystoreService(binder) ?: return grantFailureResult(
                phase = failurePhase,
                detail = "$failurePrefix: hidden IKeystoreService proxy unavailable.",
            )
            block(service, resolveConstants())
        } catch (throwable: Throwable) {
            grantFailureResult(
                phase = failurePhase,
                detail = "$failurePrefix: ${describeThrowable(throwable)}",
                errorKind = classifyFailure(throwable),
                throwable = throwable,
            )
        }
    }

    private fun readChainFromDescriptor(
        service: Any,
        descriptor: Any,
        phase: Keystore2PrivateGrantPhase,
        emptyDetail: String,
        successDetailPrefix: String,
    ): Keystore2PrivateGrantChainResult {
        val response = service.javaClass
            .getMethod("getKeyEntry", descriptor.javaClass)
            .also { it.isAccessible = true }
            .invoke(service, descriptor)
            ?: return Keystore2PrivateGrantChainResult.unavailable(
                phase = phase,
                detail = "$successDetailPrefix returned no KeyEntryResponse.",
            )
        val chain = chainFromKeyEntryResponse(response)
        if (chain.certificates.isEmpty()) {
            return Keystore2PrivateGrantChainResult.unavailable(
                phase = phase,
                detail = emptyDetail,
            )
        }
        return Keystore2PrivateGrantChainResult(
            available = true,
            phase = phase,
            chain = chain,
            detail = "$successDetailPrefix chainLength=${chain.certificates.size}",
        )
    }

    private fun grantAliasToUid(
        service: Any,
        alias: String,
        uid: Int,
        constants: Keystore2PrivateGrantConstants,
    ): Keystore2PrivateGrantResult {
        return grantAliasToUid(
            service = service,
            alias = alias,
            uid = uid,
            accessVector = constants.grantAccessVector,
            constants = constants,
        )
    }

    private fun grantAliasToUid(
        service: Any,
        alias: String,
        uid: Int,
        accessVector: Int,
        constants: Keystore2PrivateGrantConstants,
    ): Keystore2PrivateGrantResult {
        val descriptor = createDescriptor(alias, constants.domainApp)
        val grantDescriptor = service.javaClass.methods
            .firstOrNull { method ->
                method.name == "grant" &&
                    method.parameterTypes.size == 3 &&
                    method.parameterTypes[1] == Int::class.javaPrimitiveType &&
                    method.parameterTypes[2] == Int::class.javaPrimitiveType
            }
            ?.also { it.isAccessible = true }
            ?.invoke(service, descriptor, uid, accessVector)
            ?: return Keystore2PrivateGrantResult.unavailable(
                phase = Keystore2PrivateGrantPhase.PRIVATE_GRANT,
                detail = "private grant failed: hidden grant() returned no descriptor.",
            )
        val grantId = readLongField(grantDescriptor, "nspace")
        if (grantId == null) {
            return Keystore2PrivateGrantResult.unavailable(
                phase = Keystore2PrivateGrantPhase.PRIVATE_GRANT,
                detail = "private grant failed: hidden grant() returned invalid grant namespace.",
            )
        }
        return Keystore2PrivateGrantResult(
            available = true,
            phase = Keystore2PrivateGrantPhase.PRIVATE_GRANT,
            grantId = grantId,
            detail = "private grant created grantId=$grantId unsignedGrantId=${java.lang.Long.toUnsignedString(grantId)} accessVector=$accessVector",
        )
    }

    private fun revokeAliasGrant(
        service: Any,
        alias: String,
        uid: Int,
        constants: Keystore2PrivateGrantConstants,
    ): Keystore2PrivateGrantResult {
        val descriptor = createDescriptor(alias, constants.domainApp)
        val method = service.javaClass.methods
            .firstOrNull { candidate ->
                candidate.name == "ungrant" &&
                    candidate.parameterTypes.size == 2 &&
                    candidate.parameterTypes[1] == Int::class.javaPrimitiveType
            }
            ?: return Keystore2PrivateGrantResult.unavailable(
                phase = Keystore2PrivateGrantPhase.PRIVATE_UNGRANT,
                detail = "private ungrant failed: hidden ungrant() was unavailable.",
            )
        method.isAccessible = true
        method.invoke(service, descriptor, uid)
        return Keystore2PrivateGrantResult(
            available = true,
            phase = Keystore2PrivateGrantPhase.PRIVATE_UNGRANT,
            detail = "private ungrant completed uid=$uid",
        )
    }

    private fun readOwnerChain(
        service: Any,
        alias: String,
        constants: Keystore2PrivateGrantConstants,
    ): Keystore2PrivateGrantChainResult {
        return readChainFromDescriptor(
            service = service,
            descriptor = createDescriptor(alias, constants.domainApp),
            phase = Keystore2PrivateGrantPhase.PRIVATE_GET_KEY_ENTRY_APP,
            emptyDetail = "private getKeyEntry(APP) returned an empty certificate chain.",
            successDetailPrefix = "private getKeyEntry(APP)",
        )
    }

    private fun readGrantChain(
        service: Any,
        grantId: Long,
        constants: Keystore2PrivateGrantConstants,
    ): Keystore2PrivateGrantChainResult {
        return readChainFromDescriptor(
            service = service,
            descriptor = createDescriptor(grantId, constants.domainGrant),
            phase = Keystore2PrivateGrantPhase.PRIVATE_GET_KEY_ENTRY_GRANT,
            emptyDetail = "private getKeyEntry(GRANT) returned an empty certificate chain.",
            successDetailPrefix = "private getKeyEntry(GRANT)",
        )
    }

    private fun createDescriptor(alias: String, domain: Int): Any {
        val descriptorClass = loadClass(CLASS_KEY_DESCRIPTOR)
        val descriptor = descriptorClass.getDeclaredConstructor().newInstance()
        setField(descriptor, "domain", domain)
        setField(descriptor, "nspace", NAMESPACE_APPLICATION)
        setField(descriptor, "alias", alias)
        setField(descriptor, "blob", null)
        return descriptor
    }

    private fun createDescriptor(nspace: Long, domain: Int): Any {
        val descriptorClass = loadClass(CLASS_KEY_DESCRIPTOR)
        val descriptor = descriptorClass.getDeclaredConstructor().newInstance()
        setField(descriptor, "domain", domain)
        setField(descriptor, "nspace", nspace)
        setField(descriptor, "alias", null)
        setField(descriptor, "blob", null)
        return descriptor
    }

    private fun createKeystoreService(binder: IBinder): Any? {
        return runCatching {
            val stubClass = loadClass("$CLASS_IKEYSTORE_SERVICE\$Stub")
            val asInterface = stubClass.getMethod("asInterface", IBinder::class.java)
            asInterface.invoke(null, binder)
        }.getOrNull()
    }

    private fun resolveConstants(): Keystore2PrivateGrantConstants {
        return Keystore2PrivateGrantConstants(
            domainApp = resolveStaticInt(CLASS_DOMAIN, "APP", DOMAIN_APP_FALLBACK),
            domainGrant = resolveStaticInt(CLASS_DOMAIN, "GRANT", DOMAIN_GRANT_FALLBACK),
            permissionUse = resolveStaticInt(CLASS_KEY_PERMISSION, "USE", KEY_PERMISSION_USE_FALLBACK),
            permissionGetInfo = resolveStaticInt(CLASS_KEY_PERMISSION, "GET_INFO", KEY_PERMISSION_GET_INFO_FALLBACK),
            permissionUpdate = resolveStaticInt(CLASS_KEY_PERMISSION, "UPDATE", KEY_PERMISSION_UPDATE_FALLBACK),
            transactionGetKeyEntry = resolveStaticInt(
                "$CLASS_IKEYSTORE_SERVICE\$Stub",
                "TRANSACTION_getKeyEntry",
                TRANSACTION_GET_KEY_ENTRY_FALLBACK,
            ),
            transactionGrant = resolveStaticInt(
                "$CLASS_IKEYSTORE_SERVICE\$Stub",
                "TRANSACTION_grant",
                TRANSACTION_GRANT_FALLBACK,
            ),
            transactionUngrant = resolveStaticInt(
                "$CLASS_IKEYSTORE_SERVICE\$Stub",
                "TRANSACTION_ungrant",
                TRANSACTION_UNGRANT_FALLBACK,
            ),
        )
    }

    private fun resolveStaticInt(className: String, fieldName: String, fallback: Int): Int {
        return runCatching {
            val field = loadClass(className).getField(fieldName)
            field.isAccessible = true
            field.getInt(null)
        }.getOrDefault(fallback)
    }

    private fun chainFromKeyEntryResponse(response: Any): GrantDomainCertificateChain {
        val leaf = readByteArrayField(response, "certificate")
            ?: readByteArrayField(readFieldValue(response, "metadata"), "certificate")
        val remaining = readByteArrayField(response, "certificateChain")
            ?: readByteArrayField(readFieldValue(response, "metadata"), "certificateChain")
        return chainFromCertificateBlobs(leaf, remaining)
    }

    private fun classifyFailure(throwable: Throwable): Keystore2PrivateGrantErrorKind {
        val errorCode = extractServiceSpecificErrorCode(throwable)
        return classifyKeystore2PrivateGrantFailure(
            family = grantFailureFamilyOf(findRootCause(throwable)),
            message = findRootCause(throwable).message,
            serviceSpecificErrorCode = errorCode,
        )
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> grantFailureResult(
        phase: Keystore2PrivateGrantPhase,
        detail: String,
        errorKind: Keystore2PrivateGrantErrorKind = Keystore2PrivateGrantErrorKind.SERVICE_UNAVAILABLE,
        throwable: Throwable? = null,
    ): T where T : Keystore2PrivateGrantFailureResult {
        val normalizedErrorKind = if (
            phase == Keystore2PrivateGrantPhase.PRIVATE_UNGRANT &&
            errorKind == Keystore2PrivateGrantErrorKind.SERVICE_UNAVAILABLE
        ) {
            Keystore2PrivateGrantErrorKind.UNGRANT_FAILED
        } else {
            errorKind
        }
        val isChainPhase = phase == Keystore2PrivateGrantPhase.PRIVATE_GET_KEY_ENTRY_APP ||
            phase == Keystore2PrivateGrantPhase.PRIVATE_GET_KEY_ENTRY_GRANT ||
            phase == Keystore2PrivateGrantPhase.ISOLATED_BINDER_READBACK
        val result = if (isChainPhase) {
            Keystore2PrivateGrantChainResult.unavailable(
                phase = phase,
                errorKind = normalizedErrorKind,
                detail = detail,
                throwable = throwable,
            )
        } else {
            Keystore2PrivateGrantResult.unavailable(
                phase = phase,
                errorKind = normalizedErrorKind,
                detail = detail,
                throwable = throwable,
            )
        }
        return result as T
    }

    companion object {
        const val DOMAIN_APP_FALLBACK = 0
        const val DOMAIN_GRANT_FALLBACK = 1
        const val KEY_PERMISSION_GET_INFO_FALLBACK = 0x4
        const val KEY_PERMISSION_GRANT_FALLBACK = 0x8
        const val KEY_PERMISSION_UPDATE_FALLBACK = 0x80
        const val KEY_PERMISSION_USE_FALLBACK = 0x100
        const val TRANSACTION_GET_KEY_ENTRY_FALLBACK = 2
        const val TRANSACTION_GRANT_FALLBACK = 6
        const val TRANSACTION_UNGRANT_FALLBACK = 7
        const val RESPONSE_CODE_PERMISSION_DENIED = 6
        const val RESPONSE_CODE_KEY_NOT_FOUND = 7

        private const val NAMESPACE_APPLICATION = -1L
        private const val CLASS_IKEYSTORE_SERVICE = "android.system.keystore2.IKeystoreService"
        private const val CLASS_KEY_DESCRIPTOR = "android.system.keystore2.KeyDescriptor"
        private const val CLASS_DOMAIN = "android.system.keystore2.Domain"
        private const val CLASS_KEY_PERMISSION = "android.system.keystore2.KeyPermission"
    }
}
