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

package com.eltavine.duckdetector.features.customrom.data.repository

import com.eltavine.duckdetector.features.customrom.domain.CustomRomModificationFinding

private val UNLOCKED_VALUES = setOf("0", "unlocked", "false")

/**
 * An unlocked bootloader as ro.boot.flash.locked states it, or null.
 *
 * init copies the bootloader's androidboot.flash.locked into ro.boot.flash.locked, and bootloaders
 * are not required to pass it, so an empty or unreadable value says nothing about the lock state.
 */
internal fun bootloaderUnlockFinding(lockState: String?): CustomRomModificationFinding? {
    val value = lockState?.trim().orEmpty()
    if (value.lowercase() !in UNLOCKED_VALUES) {
        return null
    }
    return CustomRomModificationFinding(
        category = "Bootloader",
        signal = "ro.boot.flash.locked",
        summary = "Unlocked bootloader",
        detail = "ro.boot.flash.locked=$value",
    )
}
