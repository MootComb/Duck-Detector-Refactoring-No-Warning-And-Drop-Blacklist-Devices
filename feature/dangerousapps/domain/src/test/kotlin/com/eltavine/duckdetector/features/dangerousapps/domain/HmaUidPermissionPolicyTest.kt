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

package com.eltavine.duckdetector.features.dangerousapps.domain

import org.junit.Assert.*
import org.junit.Test

class HmaUidPermissionPolicyTest {
    private val hit = HmaUidPermissionEvidence(10043, listOf(HmaUidPermissionPolicy.PERMISSIONS.first()))
    private val baseline = HmaUidPermissionObservation(10000, 10000, true)

    @Test fun `a controlled discrepancy is experimental and has no package identity`() {
        val result = HmaUidPermissionPolicy.evaluate(baseline.copy(evidence = listOf(hit)))
        assertEquals(HmaCheckState.EXPERIMENTAL_ANOMALY, result.state)
        assertEquals(listOf(10043), result.uids)
        assertEquals(listOf(hit), result.uidPermissionEvidence)
        assertTrue(result.packages.isEmpty())
    }

    @Test fun `failed final control invalidates an already verified hit`() {
        val result = HmaUidPermissionPolicy.evaluate(baseline.copy(controlsPassed = false, evidence = listOf(hit)))
        assertEquals(HmaCheckState.INCONCLUSIVE, result.state)
        assertTrue(result.uids.isEmpty())
        assertTrue(result.uidPermissionEvidence.isEmpty())
    }

    @Test fun `a complete negative only establishes consistency in scope`() {
        assertEquals(HmaCheckState.CONSISTENT, HmaUidPermissionPolicy.evaluate(baseline).state)
        assertEquals(HmaCheckState.PARTIAL, HmaUidPermissionPolicy.evaluate(baseline.copy(checked = 0)).state)
        assertEquals(HmaCheckState.INCONCLUSIVE,
            HmaUidPermissionPolicy.evaluate(baseline.copy(unstableCandidates = 1)).state)
    }

    @Test fun `query failure remains distinct from a negative observation`() {
        for (failure in listOf(HmaCheckState.UNAVAILABLE, HmaCheckState.PERMISSION_LIMITED)) {
            assertEquals(failure, HmaUidPermissionPolicy.evaluate(baseline.copy(failureState = failure)).state)
        }
    }

    @Test fun `partial coverage retains controlled positive evidence`() {
        val result = HmaUidPermissionPolicy.evaluate(baseline.copy(checked = 44,
            evidence = listOf(hit), candidateLimitReached = true))
        assertEquals(HmaCheckState.EXPERIMENTAL_ANOMALY, result.state)
        assertTrue(result.detail.contains("44/10000"))
        assertTrue(result.detail.contains("candidate limit reached=true"))
    }

    @Test fun `unvisited foreign wrong user and instant permission evidence cannot escape`() {
        val invalid = listOf(
            baseline.copy(checked = 43, evidence = listOf(hit)),
            baseline.copy(evidence = listOf(hit.copy(uid = 110043))),
            baseline.copy(evidence = listOf(hit.copy(permissions = listOf("android.permission.INTERNET")))),
            baseline.copy(evidence = listOf(hit.copy(permissions = emptyList()))),
            baseline.copy(evidence = listOf(hit, hit)),
            baseline.copy(firstUid = 0, evidence = listOf(hit)),
        )
        for (observation in invalid) {
            val result = HmaUidPermissionPolicy.evaluate(observation)
            assertEquals(HmaCheckState.INCONCLUSIVE, result.state)
            assertTrue(result.uids.isEmpty())
        }
    }

    @Test fun `secondary Android users retain their own coordinates`() {
        val result = HmaUidPermissionPolicy.evaluate(baseline.copy(firstUid = 1010000,
            evidence = listOf(hit.copy(uid = 1010043))))
        assertEquals(listOf(1010043), result.uids)
    }

    @Test fun `correlation never changes evidence severity or counts`() {
        val task = HmaBehaviorCheck(HmaCheckKind.UID_TASK_VISIBILITY, HmaCheckState.INCONSISTENT, "Task", uids = listOf(10043))
        val permission = HmaUidPermissionPolicy.evaluate(baseline.copy(evidence = listOf(hit)))
        val result = HmaUidEvidenceCorrelation.annotate(listOf(task, permission))
        assertEquals(listOf(task.state, permission.state), result.map { it.state })
        assertEquals(listOf(task.uids, permission.uids), result.map { it.uids })
        assertTrue(result.all { it.detail.contains("adds no independent HMA confidence") })
    }
}
