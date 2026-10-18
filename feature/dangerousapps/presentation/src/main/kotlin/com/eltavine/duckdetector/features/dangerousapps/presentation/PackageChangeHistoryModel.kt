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

package com.eltavine.duckdetector.features.dangerousapps.presentation

import com.eltavine.duckdetector.features.dangerousapps.domain.PackageChangeHistory
import com.eltavine.duckdetector.features.dangerousapps.domain.PackageChangeHistoryState
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsPackageHistoryModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsTargetAppModel

internal fun PackageChangeHistory.toCardModel(): DangerousAppsPackageHistoryModel {
    val scope = "History resets on reboot and may be filtered by package visibility or hiding modules. " +
        "It cannot establish current installation, running state or concealment."
    val observation = when (state) {
        PackageChangeHistoryState.NOT_COLLECTED -> "Not collected."
        PackageChangeHistoryState.PERMISSION_DENIED -> "Permission denied; change history is unavailable."
        PackageChangeHistoryState.UNAVAILABLE -> "Query failed; change history is unavailable."
        PackageChangeHistoryState.INVALID_RESPONSE -> "Invalid response; change history could not be evaluated."
        PackageChangeHistoryState.AVAILABLE -> buildString {
            append("${matchedTargets.size} monitored package(s) appeared in visible changes since boot. ")
            append("Additions, updates and removals share this list; event type and time are not provided. ")
            if (sequenceNumber != null) {
                append("Returned sequence: $sequenceNumber.")
            } else {
                append("No visible changes or sequence number were returned.")
            }
        }
    }
    return DangerousAppsPackageHistoryModel(
        summary = "$observation $scope",
        packages = if (state == PackageChangeHistoryState.AVAILABLE) {
            matchedTargets.map { target ->
                DangerousAppsTargetAppModel(target.appName, target.packageName, target.category.displayName)
            }
        } else {
            emptyList()
        },
    )
}
