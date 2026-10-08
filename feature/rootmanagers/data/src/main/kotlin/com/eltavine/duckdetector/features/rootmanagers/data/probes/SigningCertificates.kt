/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.rootmanagers.data.probes

import android.content.pm.PackageInfo
import com.eltavine.duckdetector.features.rootmanagers.domain.CertificateFingerprint
import java.security.MessageDigest

/**
 * Fingerprints the certificates PackageManager reports for a package.
 *
 * `Signature.toByteArray()` is the DER encoding of each signer's own certificate, the first entry of
 * that signer's chain in the APK signature block, so its length and SHA-256 are the same pair a
 * KernelSU-family kernel computes in `kernel/manager/apk_sign.c`. The rotation history is included
 * so a manager that rotated its key still shows the original one the kernel was built against.
 */
internal object SigningCertificates {

    /** Null when PackageManager returned no signing information, which is a failed read, not a match. */
    fun of(packageInfo: PackageInfo): List<CertificateFingerprint>? {
        val signingInfo = packageInfo.signingInfo ?: return null
        val signatures = buildList {
            addAll(signingInfo.apkContentsSigners.orEmpty())
            if (!signingInfo.hasMultipleSigners()) {
                addAll(signingInfo.signingCertificateHistory.orEmpty())
            }
        }
        return signatures.map { signature -> fingerprint(signature.toByteArray()) }.distinct()
    }

    fun fingerprint(der: ByteArray): CertificateFingerprint = CertificateFingerprint(
        sizeBytes = der.size,
        sha256 = MessageDigest.getInstance("SHA-256").digest(der).toLowerHex(),
    )

    private fun ByteArray.toLowerHex(): String = buildString(size * 2) {
        for (byte in this@toLowerHex) {
            val value = byte.toInt() and 0xff
            append(HEX_DIGITS[value ushr 4])
            append(HEX_DIGITS[value and 0x0f])
        }
    }

    private const val HEX_DIGITS = "0123456789abcdef"
}
