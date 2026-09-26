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
import android.media.MediaDrmThrowable
import android.os.Build
import androidx.annotation.RequiresApi
import java.util.UUID

internal object AndroidWidevineDrmErrorMetadataReader : WidevineDrmErrorMetadataReader {

    override fun read(throwable: Exception): WidevineDrmErrorMetadata {
        val stateException = throwable as? MediaDrmStateException
        val sessionException = throwable as? SessionException
        val api34Metadata = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            Api34.read(throwable)
        } else {
            WidevineDrmErrorMetadata()
        }
        return api34Metadata.copy(
            errorCode = when {
                stateException != null -> stateException.sanitizedErrorCode()
                sessionException != null -> sessionException.sanitizedErrorCode()
                else -> null
            },
            transient = when {
                stateException != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
                    stateException.isTransient

                sessionException != null -> sessionException.isTransientCompat()
                else -> null
            },
        )
    }

    private fun MediaDrmStateException.sanitizedErrorCode(): Int? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return errorCode
        }
        val match = LEGACY_DIAGNOSTIC_ERROR.find(diagnosticInfo) ?: return null
        val magnitude = match.groupValues[2].toIntOrNull() ?: return null
        return if (match.groupValues[1].isNotEmpty()) -magnitude else magnitude
    }

    @Suppress("DEPRECATION")
    private fun SessionException.sanitizedErrorCode(): Int = errorCode

    @Suppress("DEPRECATION")
    private fun SessionException.isTransientCompat(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            isTransient
        } else {
            errorCode == SessionException.ERROR_RESOURCE_CONTENTION
        }
    }

    private val LEGACY_DIAGNOSTIC_ERROR = Regex("error_(neg_)?(\\d+)")

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    private object Api34 {
        fun read(throwable: Throwable): WidevineDrmErrorMetadata {
            val mediaDrmThrowable = throwable as? MediaDrmThrowable
                ?: return WidevineDrmErrorMetadata()
            return WidevineDrmErrorMetadata(
                vendorError = mediaDrmThrowable.vendorError,
                oemError = mediaDrmThrowable.oemError,
                errorContext = mediaDrmThrowable.errorContext,
            )
        }
    }
}

internal object AndroidWidevineMediaDrmFactory : WidevineMediaDrmFactory {
    private val widevineUuid = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")

    override fun isCryptoSchemeSupported(): Boolean {
        return MediaDrm.isCryptoSchemeSupported(widevineUuid)
    }

    override fun isHardwareSecureAllSupported(): Boolean {
        return MediaDrm.isCryptoSchemeSupported(
            widevineUuid,
            WIDEVINE_TEST_MIME_TYPE,
            MediaDrm.SECURITY_LEVEL_HW_SECURE_ALL,
        )
    }

    override fun create(): WidevineMediaDrmClient {
        return AndroidWidevineMediaDrmClient(MediaDrm(widevineUuid))
    }
}

private class AndroidWidevineMediaDrmClient(
    private val mediaDrm: MediaDrm,
) : WidevineMediaDrmClient {

    override fun getPropertyString(name: String): String = mediaDrm.getPropertyString(name)

    override fun openMaximumSecuritySession(): ByteArray {
        return mediaDrm.openSession()
    }

    override fun getSecurityLevel(sessionId: ByteArray): WidevineSessionSecurityLevel {
        return when (mediaDrm.getSecurityLevel(sessionId)) {
            MediaDrm.SECURITY_LEVEL_SW_SECURE_CRYPTO ->
                WidevineSessionSecurityLevel.SW_SECURE_CRYPTO

            MediaDrm.SECURITY_LEVEL_SW_SECURE_DECODE ->
                WidevineSessionSecurityLevel.SW_SECURE_DECODE

            MediaDrm.SECURITY_LEVEL_HW_SECURE_CRYPTO ->
                WidevineSessionSecurityLevel.HW_SECURE_CRYPTO

            MediaDrm.SECURITY_LEVEL_HW_SECURE_DECODE ->
                WidevineSessionSecurityLevel.HW_SECURE_DECODE

            MediaDrm.SECURITY_LEVEL_HW_SECURE_ALL ->
                WidevineSessionSecurityLevel.HW_SECURE_ALL

            else -> WidevineSessionSecurityLevel.UNKNOWN
        }
    }

    override fun hasDeviceUniqueId(): Boolean {
        val deviceUniqueId = mediaDrm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)
        return try {
            deviceUniqueId.isNotEmpty()
        } finally {
            deviceUniqueId.fill(0)
        }
    }

    override fun generateTestKeyRequest(sessionId: ByteArray) {
        val request = mediaDrm.getKeyRequest(
            sessionId,
            TEST_PSSH.copyOf(),
            WIDEVINE_TEST_MIME_TYPE,
            MediaDrm.KEY_TYPE_STREAMING,
            hashMapOf(),
        )
        request.data.fill(0)
    }

    override fun closeSession(sessionId: ByteArray) {
        mediaDrm.closeSession(sessionId)
    }

    override fun close() {
        mediaDrm.close()
    }

    private companion object {
        // Common Encryption PSSH v0 with the Widevine system ID and a fixed non-secret test KID.
        val TEST_PSSH = intArrayOf(
            0x00, 0x00, 0x00, 0x32,
            0x70, 0x73, 0x73, 0x68,
            0x00, 0x00, 0x00, 0x00,
            0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce,
            0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
            0x00, 0x00, 0x00, 0x12,
            0x12, 0x10,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ).map(Int::toByte).toByteArray()
    }
}
