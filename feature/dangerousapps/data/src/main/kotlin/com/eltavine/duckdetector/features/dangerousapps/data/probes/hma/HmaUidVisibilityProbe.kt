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

package com.eltavine.duckdetector.features.dangerousapps.data.probes.hma

import android.content.Context
import android.os.Process
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaBehaviorCheck
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckKind
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckState
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaUidVisibilityObservation
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaUidVisibilityPolicy
import kotlinx.coroutines.ensureActive
import kotlin.coroutines.coroutineContext

internal class HmaUidVisibilityProbe(
    private val self: Int,
    private val packageName: String,
    private val scanTasks: (Int, Int) -> UidTaskSnapshot,
    private val calls: HmaUidPackageCalls,
) {
    constructor(
        context: Context,
        bridge: HmaUidTaskBridge = HmaUidTaskBridge(),
        calls: HmaUidPackageCalls = HmaPackageManagerBinder(),
    ) : this(Process.myUid(), context.packageName, bridge::scan, calls)

    suspend fun run(visibility: DangerousPackageVisibility): HmaBehaviorCheck {
        val kind = HmaCheckKind.UID_TASK_VISIBILITY
        if (visibility != DangerousPackageVisibility.FULL) {
            return HmaBehaviorCheck(kind, HmaCheckState.PERMISSION_LIMITED,
                "Full package visibility is required to compare UID tasks with package associations.")
        }
        val base = self / HmaPlatformCalls.PER_USER_RANGE * HmaPlatformCalls.PER_USER_RANGE
        if (self - base !in 10000..19999) {
            return HmaBehaviorCheck(kind, HmaCheckState.UNSUPPORTED, "Caller is outside the ordinary application UID range.")
        }
        val snapshot = scanTasks(base + 10000, base + 19999)
        if (snapshot.status !in setOf(HmaUidTaskBridge.COMPLETE, HmaUidTaskBridge.PARTIAL)) {
            return HmaBehaviorCheck(kind, when (snapshot.status) {
                HmaUidTaskBridge.RESTRICTED -> HmaCheckState.PERMISSION_LIMITED
                HmaUidTaskBridge.TIMEOUT -> HmaCheckState.INCONCLUSIVE
                else -> HmaCheckState.UNAVAILABLE
            }, "Native child status=${snapshot.status}, errno/signal=${snapshot.error}. ${snapshot.failure}")
        }
        val unassociated = mutableListOf<Int>()
        var associationFailure = false
        var queryFailure: HmaUidCallFailure? = null
        fun recordFailure(result: Result<*>) {
            result.exceptionOrNull()?.let { if (queryFailure == null) queryFailure = HmaUidCallFailure.from(it) }
        }
        // Verify the association service before and after comparing foreign UIDs.
        val beforeQuery = freshQuery { packageName in calls.packages(self) }
        recordFailure(beforeQuery)
        val before = beforeQuery.getOrDefault(false)
        var candidates = 0
        if (before) for (uid in snapshot.tasks.keys) {
            coroutineContext.ensureActive()
            val packages = freshQuery { calls.packages(uid) }
            if (packages.isFailure) { recordFailure(packages); associationFailure = true; continue }
            if (!packages.getOrNull().isNullOrEmpty()) continue
            candidates++
            if (candidates > MAX_RECHECKS) break
            val repeated = scanTasks(uid, uid)
            if (repeated.status != HmaUidTaskBridge.COMPLETE) associationFailure = true
            val stillUnassociated = freshQuery { calls.packages(uid).isEmpty() }
            if (stillUnassociated.isFailure) { recordFailure(stillUnassociated); associationFailure = true }
            if (repeated.status == HmaUidTaskBridge.COMPLETE && uid in repeated.tasks &&
                stillUnassociated.getOrNull() == true) unassociated += uid
        }
        val afterQuery = freshQuery { packageName in calls.packages(self) }
        recordFailure(afterQuery)
        val after = afterQuery.getOrDefault(false)
        return HmaUidVisibilityPolicy.evaluate(HmaUidVisibilityObservation(
            complete = snapshot.status == HmaUidTaskBridge.COMPLETE,
            checked = snapshot.checked,
            firstUid = base + 10000,
            taskUids = snapshot.tasks.keys,
            callerUid = self,
            callerAssociationBefore = before,
            callerAssociationAfter = after,
            unassociated = unassociated,
            verificationFailed = associationFailure,
            verificationLimitReached = candidates > MAX_RECHECKS,
            queryFailureState = queryFailure?.state,
            queryFailureDetail = queryFailure?.detail.orEmpty(),
        ))
    }

    private inline fun <T> freshQuery(block: () -> T): Result<T> = try {
        Result.success(block())
    } catch (cause: Exception) {
        HmaUidCallFailure.from(cause) // Cancellation must escape, never become a missing association.
        Result.failure(cause)
    } catch (cause: LinkageError) {
        Result.failure(cause)
    }

    private companion object { const val MAX_RECHECKS = 16 }
}
