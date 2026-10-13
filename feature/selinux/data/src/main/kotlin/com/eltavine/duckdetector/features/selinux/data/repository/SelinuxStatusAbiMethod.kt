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

package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxStatusAbiRequestKind
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxStatusAbiSnapshot
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxStatusAbiState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStatusAbiReading
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStatusAbiRequest
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStatusAbiVerdict

internal fun buildStatusAbiMethod(snapshot: SelinuxStatusAbiSnapshot): SelinuxCheckResult {
    val reading = SelinuxStatusAbiReading(
        verdict = when (snapshot.state) {
            SelinuxStatusAbiState.VIOLATION -> SelinuxStatusAbiVerdict.ABI_VIOLATION
            SelinuxStatusAbiState.NO_VIOLATION -> SelinuxStatusAbiVerdict.NO_VIOLATION
            SelinuxStatusAbiState.UNAVAILABLE -> SelinuxStatusAbiVerdict.UNAVAILABLE
            SelinuxStatusAbiState.INCONCLUSIVE -> SelinuxStatusAbiVerdict.INCONCLUSIVE
        },
        violatedRequests = snapshot.violatedRequests.mapNotNull { kind -> kind.toDomain() },
        pageSize = snapshot.pageSize,
        notes = snapshot.notes,
    )
    return SelinuxCheckResult(
        method = SelinuxOracle.STATUS_MMAP_ABI.label,
        status = reading.verdict.label,
        isSecure = when (reading.verdict) {
            // Only a granted nonconforming request is evidence; every other outcome states what
            // was observed and cannot exclude a hidden handler.
            SelinuxStatusAbiVerdict.ABI_VIOLATION -> false
            else -> null
        },
        permissionDenied = false,
        details = details(reading, snapshot.failureReason),
        oracle = SelinuxOracle.STATUS_MMAP_ABI,
        statusAbi = reading,
    )
}

private fun details(reading: SelinuxStatusAbiReading, failureReason: String?): String? {
    return when (reading.verdict) {
        SelinuxStatusAbiVerdict.ABI_VIOLATION ->
            "The status node granted requests stock selinuxfs rejects: " +
                reading.violatedRequests.joinToString { it.label } + "." +
                failureReason?.let { " The request set did not finish: $it" }.orEmpty()
        SelinuxStatusAbiVerdict.NO_VIOLATION ->
            "Every nonconforming mmap/mprotect request to the status node was rejected, like stock " +
                "selinuxfs. A handler that keeps the upstream checks answers the same way."
        SelinuxStatusAbiVerdict.UNAVAILABLE, SelinuxStatusAbiVerdict.INCONCLUSIVE -> failureReason
    }
}

private fun SelinuxStatusAbiRequestKind.toDomain(): SelinuxStatusAbiRequest? {
    return when (this) {
        SelinuxStatusAbiRequestKind.TWO_PAGE_SHARED -> SelinuxStatusAbiRequest.TWO_PAGE_SHARED
        SelinuxStatusAbiRequestKind.OFFSET_SHARED -> SelinuxStatusAbiRequest.OFFSET_SHARED
        SelinuxStatusAbiRequestKind.WRITABLE_PRIVATE -> SelinuxStatusAbiRequest.WRITABLE_PRIVATE
        SelinuxStatusAbiRequestKind.MPROTECT_WRITE -> SelinuxStatusAbiRequest.MPROTECT_WRITE
    }
}
