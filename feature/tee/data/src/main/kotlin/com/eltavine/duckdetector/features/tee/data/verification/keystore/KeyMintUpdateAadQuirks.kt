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
import com.eltavine.duckdetector.core.platform.HiddenSystemProperties

/** The build fields that name a device's vendor KeyMint. They are spoofable, so they only relax a check. */
internal data class KeyMintVendorIdentity(
    val manufacturer: String,
    val brand: String,
    val hardware: String,
    val roHardware: String?,
) {
    companion object {
        fun current(): KeyMintVendorIdentity = KeyMintVendorIdentity(
            manufacturer = Build.MANUFACTURER,
            brand = Build.BRAND,
            hardware = Build.HARDWARE,
            roHardware = HiddenSystemProperties.read("ro.hardware", "").getOrNull()?.takeIf { it.isNotBlank() },
        )
    }
}

/**
 * Whether this vendor's KeyMint is known to accept updateAad on a non-AEAD operation.
 *
 * IKeyMintOperation.aidl (hardware/interfaces security/keymint) says updateAad "only applies to
 * AEAD modes" but names no error for other operations, and keystore2 forwards the call without
 * checking the mode (system/security keystore2/src/operation.rs). AOSP's reference TA rejects it
 * (system/keymint ta/src/operation.rs), while Samsung devices and Xiaomi devices on MediaTek accept
 * it. Acceptance elsewhere is therefore a difference from the reference, not a contract violation.
 */
internal fun updateAadAcceptanceExpected(identity: KeyMintVendorIdentity): Boolean {
    val manufacturer = identity.manufacturer.lowercase()
    val brand = identity.brand.lowercase()
    if (manufacturer == SAMSUNG || brand == SAMSUNG) return true
    if (manufacturer != XIAOMI && brand !in XIAOMI_BRANDS) return false
    return identity.roHardware?.startsWith(MEDIATEK_HARDWARE_PREFIX) == true ||
        identity.hardware.startsWith(MEDIATEK_HARDWARE_PREFIX, ignoreCase = true)
}

private const val SAMSUNG = "samsung"
private const val XIAOMI = "xiaomi"
private val XIAOMI_BRANDS = setOf("xiaomi", "redmi", "poco")
private const val MEDIATEK_HARDWARE_PREFIX = "mt"
