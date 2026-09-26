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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxDirtyPolicyTrustTest {

    private val trusted = SelinuxContextValiditySnapshot(
        dirtyPolicyAvailable = true,
        dirtyPolicyProbeAttempted = true,
        dirtyPolicyCarrierMatchesExpected = true,
        dirtyPolicyStable = true,
        dirtyPolicyControlsPassed = true,
        dirtyPolicyAccessControlAllowed = true,
        dirtyPolicyNegativeControlRejected = true,
        javaDirtyPolicyAvailable = true,
        javaDirtyPolicyProbeAttempted = true,
        javaDirtyPolicyCarrierMatchesExpected = true,
        javaDirtyPolicyStable = true,
        javaDirtyPolicyControlsPassed = true,
        javaDirtyPolicyAccessControlAllowed = true,
        javaDirtyPolicyNegativeControlRejected = true,
    )

    @Test
    fun `an oracle that passed every check is trusted`() {
        assertTrue(trusted.dirtyPolicyTrusted)
        assertTrue(trusted.javaDirtyPolicyTrusted)
    }

    @Test
    fun `any failed check withdraws trust from that oracle only`() {
        listOf(
            trusted.copy(dirtyPolicyCarrierMatchesExpected = false),
            trusted.copy(dirtyPolicyStable = false),
            trusted.copy(dirtyPolicyControlsPassed = false),
            trusted.copy(dirtyPolicyAccessControlAllowed = null),
            trusted.copy(dirtyPolicyNegativeControlRejected = false),
        ).forEach { snapshot ->
            assertFalse(snapshot.toString(), snapshot.dirtyPolicyTrusted)
            assertTrue(snapshot.javaDirtyPolicyTrusted)
        }
        assertFalse(trusted.copy(javaDirtyPolicyNegativeControlRejected = null).javaDirtyPolicyTrusted)
    }
}
