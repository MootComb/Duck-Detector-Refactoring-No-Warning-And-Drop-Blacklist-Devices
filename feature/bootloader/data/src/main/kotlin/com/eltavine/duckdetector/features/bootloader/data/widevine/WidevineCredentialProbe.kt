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

package com.eltavine.duckdetector.features.bootloader.data.widevine

import android.media.MediaDrm
import android.media.MediaDrm.MediaDrmStateException
import android.media.MediaDrm.SessionException
import android.media.NotProvisionedException
import android.media.ResourceBusyException
import android.media.UnsupportedSchemeException
import android.os.Build

internal fun interface WidevineCredentialSource {
    fun collect(): WidevineCredentialSnapshot
}

internal interface WidevineMediaDrmFactory {
    fun isCryptoSchemeSupported(): Boolean

    fun isHardwareSecureAllSupported(): Boolean

    fun create(): WidevineMediaDrmClient
}

internal interface WidevineMediaDrmClient : AutoCloseable {
    fun getPropertyString(name: String): String

    fun openMaximumSecuritySession(): ByteArray

    fun getSecurityLevel(sessionId: ByteArray): WidevineSessionSecurityLevel

    fun hasDeviceUniqueId(): Boolean

    fun generateTestKeyRequest(sessionId: ByteArray)

    fun closeSession(sessionId: ByteArray)
}

internal data class WidevineDrmErrorMetadata(
    val errorCode: Int? = null,
    val vendorError: Int? = null,
    val oemError: Int? = null,
    val errorContext: Int? = null,
    val transient: Boolean? = null,
)

internal fun interface WidevineDrmErrorMetadataReader {
    fun read(throwable: Exception): WidevineDrmErrorMetadata
}

internal class WidevineCredentialProbe(
    private val mediaDrmFactory: WidevineMediaDrmFactory = AndroidWidevineMediaDrmFactory,
    private val nativePropertyReader: WidevineNativePropertyReader = WidevineNativeBridge(),
    private val errorMetadataReader: WidevineDrmErrorMetadataReader =
        AndroidWidevineDrmErrorMetadataReader,
) : WidevineCredentialSource {

    override fun collect(): WidevineCredentialSnapshot {
        val errors = mutableListOf<WidevineDrmError>()
        val supported = try {
            mediaDrmFactory.isCryptoSchemeSupported()
        } catch (throwable: Exception) {
            errors += sanitizeError(WidevineDrmErrorStage.SUPPORT_CHECK, throwable)
            return WidevineCredentialSnapshot(errors = errors)
        }
        if (!supported) {
            return WidevineCredentialSnapshot(schemeSupported = false)
        }

        val hardwareSecureAllSupported = try {
            mediaDrmFactory.isHardwareSecureAllSupported()
        } catch (throwable: Exception) {
            errors += sanitizeError(WidevineDrmErrorStage.SESSION_CAPABILITY, throwable)
            null
        }
        val nativeSnapshot = nativePropertyReader.readProperties()
        var javaSecurityLevel = WidevinePropertyRead()
        var javaSystemId = WidevinePropertyRead()
        var sessionStatus = WidevineOperationStatus.NOT_ATTEMPTED
        var actualSecurityLevel: WidevineSessionSecurityLevel? = null
        var credentialStatus = WidevineOperationStatus.NOT_ATTEMPTED
        var credentialAvailable: Boolean? = null
        var keyRequestStatus = WidevineOperationStatus.NOT_ATTEMPTED
        var mediaDrm: WidevineMediaDrmClient? = null
        var sessionId: ByteArray? = null

        try {
            mediaDrm = try {
                mediaDrmFactory.create()
            } catch (throwable: Exception) {
                errors += sanitizeError(WidevineDrmErrorStage.CREATE, throwable)
                null
            }

            if (mediaDrm != null) {
                javaSecurityLevel = readProperty(
                    stage = WidevineDrmErrorStage.JAVA_SECURITY_LEVEL,
                    errors = errors,
                ) {
                    mediaDrm.getPropertyString(PROPERTY_SECURITY_LEVEL)
                }
                javaSystemId = readProperty(
                    stage = WidevineDrmErrorStage.JAVA_SYSTEM_ID,
                    errors = errors,
                ) {
                    mediaDrm.getPropertyString(PROPERTY_SYSTEM_ID)
                }

                try {
                    val openedSession = mediaDrm.openMaximumSecuritySession()
                    if (openedSession.isEmpty()) {
                        errors += WidevineDrmError(
                            stage = WidevineDrmErrorStage.SESSION_OPEN,
                            kind = WidevineDrmErrorKind.INVALID_SESSION_ID,
                        )
                        sessionStatus = WidevineOperationStatus.FAILURE
                    } else {
                        sessionId = openedSession
                        sessionStatus = WidevineOperationStatus.SUCCESS
                    }
                } catch (throwable: Exception) {
                    val error = sanitizeError(WidevineDrmErrorStage.SESSION_OPEN, throwable)
                    errors += error
                    sessionStatus = error.toOperationStatus()
                }

                sessionId?.let { openedSession ->
                    try {
                        actualSecurityLevel = mediaDrm.getSecurityLevel(openedSession)
                    } catch (throwable: Exception) {
                        errors += sanitizeError(
                            WidevineDrmErrorStage.SESSION_SECURITY_LEVEL,
                            throwable,
                        )
                    }
                }

                try {
                    credentialAvailable = mediaDrm.hasDeviceUniqueId()
                    credentialStatus = WidevineOperationStatus.SUCCESS
                } catch (throwable: Exception) {
                    val error = sanitizeError(
                        WidevineDrmErrorStage.CREDENTIAL_AVAILABILITY,
                        throwable,
                    )
                    errors += error
                    credentialStatus = error.toOperationStatus()
                }

                sessionId?.let { openedSession ->
                    try {
                        mediaDrm.generateTestKeyRequest(openedSession)
                        keyRequestStatus = WidevineOperationStatus.SUCCESS
                    } catch (throwable: Exception) {
                        val error = sanitizeError(WidevineDrmErrorStage.KEY_REQUEST, throwable)
                        errors += error
                        keyRequestStatus = error.toOperationStatus()
                    }
                }
            }
        } finally {
            val client = mediaDrm
            val openedSession = sessionId
            try {
                if (client != null && openedSession != null) {
                    try {
                        client.closeSession(openedSession)
                    } catch (throwable: Exception) {
                        errors += sanitizeError(WidevineDrmErrorStage.SESSION_CLOSE, throwable)
                    } finally {
                        openedSession.fill(0)
                    }
                }
            } finally {
                if (client != null) {
                    try {
                        client.close()
                    } catch (throwable: Exception) {
                        errors += sanitizeError(WidevineDrmErrorStage.RELEASE, throwable)
                    }
                }
            }
        }

        return WidevineCredentialSnapshot(
            schemeSupported = true,
            hardwareSecureAllSupported = hardwareSecureAllSupported,
            javaSecurityLevel = javaSecurityLevel,
            javaSystemId = javaSystemId,
            native = nativeSnapshot,
            sessionStatus = sessionStatus,
            actualSessionSecurityLevel = actualSecurityLevel,
            credentialStatus = credentialStatus,
            credentialAvailable = credentialAvailable,
            keyRequestStatus = keyRequestStatus,
            errors = errors.toList(),
        )
    }

    private fun readProperty(
        stage: WidevineDrmErrorStage,
        errors: MutableList<WidevineDrmError>,
        block: () -> String,
    ): WidevinePropertyRead {
        return try {
            val value = block()
            if (value.isValidWidevinePropertyValue()) {
                WidevinePropertyRead(
                    status = WidevinePropertyStatus.AVAILABLE,
                    value = value,
                )
            } else {
                errors += WidevineDrmError(
                    stage = stage,
                    kind = WidevineDrmErrorKind.INVALID_PROPERTY_VALUE,
                )
                WidevinePropertyRead(status = WidevinePropertyStatus.ERROR)
            }
        } catch (throwable: Exception) {
            val error = sanitizeError(stage, throwable)
            errors += error
            WidevinePropertyRead(
                status = if (error.kind == WidevineDrmErrorKind.UNSUPPORTED_PROPERTY) {
                    WidevinePropertyStatus.UNSUPPORTED
                } else {
                    WidevinePropertyStatus.ERROR
                },
            )
        }
    }

    private fun sanitizeError(
        stage: WidevineDrmErrorStage,
        throwable: Exception,
    ): WidevineDrmError {
        val stateException = throwable as? MediaDrmStateException
        val sessionException = throwable as? SessionException
        val numericMetadata = try {
            errorMetadataReader.read(throwable)
        } catch (_: Exception) {
            WidevineDrmErrorMetadata()
        }
        val unsupportedProperty = stage.isPropertyStage() && (
            throwable is IllegalArgumentException ||
                throwable is UnsupportedOperationException ||
                stateException != null &&
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                numericMetadata.errorCode == MediaDrm.ErrorCodes.ERROR_UNSUPPORTED_OPERATION
        )
        return WidevineDrmError(
            stage = stage,
            kind = when {
                throwable is UnsupportedSchemeException -> WidevineDrmErrorKind.UNSUPPORTED_SCHEME
                throwable is NotProvisionedException -> WidevineDrmErrorKind.NOT_PROVISIONED
                throwable is ResourceBusyException -> WidevineDrmErrorKind.RESOURCE_BUSY
                sessionException != null && numericMetadata.transient == true ->
                    WidevineDrmErrorKind.RESOURCE_BUSY

                unsupportedProperty -> WidevineDrmErrorKind.UNSUPPORTED_PROPERTY
                stateException != null || sessionException != null -> WidevineDrmErrorKind.STATE
                else -> WidevineDrmErrorKind.RUNTIME
            },
            errorCode = numericMetadata.errorCode,
            vendorError = numericMetadata.vendorError,
            oemError = numericMetadata.oemError,
            errorContext = numericMetadata.errorContext,
            transient = numericMetadata.transient,
        )
    }

    private fun WidevineDrmErrorStage.isPropertyStage(): Boolean {
        return this == WidevineDrmErrorStage.JAVA_SECURITY_LEVEL ||
            this == WidevineDrmErrorStage.JAVA_SYSTEM_ID
    }

    private fun WidevineDrmError.toOperationStatus(): WidevineOperationStatus {
        return when {
            kind == WidevineDrmErrorKind.UNSUPPORTED_SCHEME ||
                kind == WidevineDrmErrorKind.UNSUPPORTED_PROPERTY ->
                WidevineOperationStatus.UNSUPPORTED

            kind == WidevineDrmErrorKind.NOT_PROVISIONED ->
                WidevineOperationStatus.NOT_PROVISIONED

            kind == WidevineDrmErrorKind.RESOURCE_BUSY ->
                WidevineOperationStatus.RESOURCE_BUSY

            transient == true -> WidevineOperationStatus.TRANSIENT_ERROR
            else -> WidevineOperationStatus.FAILURE
        }
    }

    private companion object {
        const val PROPERTY_SECURITY_LEVEL = "securityLevel"
        const val PROPERTY_SYSTEM_ID = "systemId"
    }
}

internal const val WIDEVINE_TEST_MIME_TYPE = "video/mp4"
