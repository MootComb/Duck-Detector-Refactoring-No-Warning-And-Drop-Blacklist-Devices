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
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GrantReflection.readByteArrayField
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GrantReflection.readFieldValue

internal fun Keystore2PrivateGrantClient.readOwnerChain(alias: String): Keystore2PrivateGrantChainResult {
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

internal fun Keystore2PrivateGrantClient.readOwnerChain(service: Any, alias: String): Keystore2PrivateGrantChainResult {
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

internal fun Keystore2PrivateGrantClient.readGrantChain(grantId: Long): Keystore2PrivateGrantChainResult {
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

internal fun Keystore2PrivateGrantClient.readGrantChain(service: Any, grantId: Long): Keystore2PrivateGrantChainResult {
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

internal fun Keystore2PrivateGrantClient.readGrantEntry(service: Any, grantId: Long): Keystore2PrivateGrantResult {
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

internal fun Keystore2PrivateGrantClient.readGrantChain(
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

internal fun Keystore2PrivateGrantClient.readChainFromDescriptor(
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

internal fun Keystore2PrivateGrantClient.readOwnerChain(
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

internal fun Keystore2PrivateGrantClient.readGrantChain(
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

internal fun Keystore2PrivateGrantClient.chainFromKeyEntryResponse(response: Any): GrantDomainCertificateChain {
    val leaf = readByteArrayField(response, "certificate")
        ?: readByteArrayField(readFieldValue(response, "metadata"), "certificate")
    val remaining = readByteArrayField(response, "certificateChain")
        ?: readByteArrayField(readFieldValue(response, "metadata"), "certificateChain")
    return chainFromCertificateBlobs(leaf, remaining)
}
