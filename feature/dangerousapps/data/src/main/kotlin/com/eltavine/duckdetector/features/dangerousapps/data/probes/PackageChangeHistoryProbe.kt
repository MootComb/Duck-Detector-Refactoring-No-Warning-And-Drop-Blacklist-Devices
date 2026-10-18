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

package com.eltavine.duckdetector.features.dangerousapps.data.probes

import android.content.Context
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppTarget
import com.eltavine.duckdetector.features.dangerousapps.domain.PackageChangeHistory
import com.eltavine.duckdetector.features.dangerousapps.domain.PackageChangeHistoryState
import kotlin.coroutines.cancellation.CancellationException

internal data class PackageChangesSnapshot(
    val sequenceNumber: Int,
    val packageNames: List<String?>,
)

class PackageChangeHistoryProbe internal constructor(
    private val query: (Int) -> PackageChangesSnapshot?,
) {
    constructor(context: Context) : this({ sequenceNumber ->
        context.packageManager.getChangedPackages(sequenceNumber)?.let { changes ->
            PackageChangesSnapshot(changes.sequenceNumber, changes.packageNames.toList())
        }
    })

    fun run(targets: List<DangerousAppTarget>): PackageChangeHistory {
        return try {
            // PackageManager.getChangedPackages is available since API 26 (project minSdk: 29).
            // Sequence zero queries this boot on every scan; a persisted cursor loses evidence
            // after a reboot. AOSP PackageManagerService filters against current package state,
            // so removed targets can still occur here. See the owning EVIDENCE.md.
            val changes = query(0)
            if (changes == null) {
                PackageChangeHistory(PackageChangeHistoryState.AVAILABLE)
            } else if (changes.sequenceNumber <= 0 || changes.packageNames.any { it.isNullOrBlank() }) {
                PackageChangeHistory(PackageChangeHistoryState.INVALID_RESPONSE)
            } else {
                val names = changes.packageNames.toHashSet()
                PackageChangeHistory(
                    state = PackageChangeHistoryState.AVAILABLE,
                    matchedTargets = targets.distinctBy { it.packageName }.filter { it.packageName in names },
                    sequenceNumber = changes.sequenceNumber,
                )
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: SecurityException) {
            PackageChangeHistory(PackageChangeHistoryState.PERMISSION_DENIED)
        } catch (_: Exception) {
            PackageChangeHistory(PackageChangeHistoryState.UNAVAILABLE)
        }
    }
}
