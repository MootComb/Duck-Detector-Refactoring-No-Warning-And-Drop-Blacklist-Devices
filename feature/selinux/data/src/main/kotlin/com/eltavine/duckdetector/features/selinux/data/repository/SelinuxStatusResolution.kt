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

package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode

internal fun determineStatusWithParadoxLogic(
    results: List<SelinuxCheckResult>,
): StatusResolution {
    val filesystemActive = results.any {
        it.method == METHOD_FILESYSTEM && (it.status == FILESYSTEM_ACTIVE || it.status == FILESYSTEM_MOUNTED)
    }

    results.forEach { result ->
        if (result.status == SELINUX_PERMISSIVE) {
            return StatusResolution(
                SelinuxMode.PERMISSIVE,
                SELINUX_PERMISSIVE,
                paradoxDetected = false
            )
        }
        if (result.status == SELINUX_DISABLED || result.status == FILESYSTEM_NOT_MOUNTED) {
            return StatusResolution(
                SelinuxMode.DISABLED,
                SELINUX_DISABLED,
                paradoxDetected = false
            )
        }
    }

    if (results.any { it.readsEnforcing }) {
        return StatusResolution(
            SelinuxMode.ENFORCING,
            SELINUX_ENFORCING,
            paradoxDetected = false
        )
    }

    // Only a denied read of the enforce node proves enforcing mode: every UID may read it (S_IRUGO
    // in security/selinux/selinuxfs.c), and in permissive mode avc_denied() grants instead of
    // returning -EACCES (security/selinux/avc.c).
    val enforceReadDenied = results.any { it.permissionDenied && it.method in ENFORCE_NODE_METHODS }
    if (enforceReadDenied && filesystemActive) {
        return StatusResolution(
            SelinuxMode.ENFORCING,
            "Enforcing (paradox)",
            paradoxDetected = true
        )
    }

    return StatusResolution(SelinuxMode.UNKNOWN, "Unknown", paradoxDetected = false)
}

internal data class StatusResolution(
    val mode: SelinuxMode,
    val label: String,
    val paradoxDetected: Boolean,
)
