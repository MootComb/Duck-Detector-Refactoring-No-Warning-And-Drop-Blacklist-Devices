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

package com.eltavine.duckdetector.sdk

import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledApplicationRecord
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageInventory
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageInventoryResult
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.capability.packageinventory.domain.PackageInventoryFailure
import com.eltavine.duckdetector.capability.packageinventory.domain.PackageInventoryFailureKind
import org.junit.Assert.assertEquals
import org.junit.Test

class PackageVisibilityTest {

    private fun inventory(visibility: InstalledPackageVisibility, suspiciouslyLow: Boolean) =
        InstalledPackageInventoryResult.Available(
            InstalledPackageInventory(
                applications = listOf("a.one", "a.two", "a.two").map { InstalledApplicationRecord(it, it, emptySet()) },
                visibility = visibility,
                suspiciouslyLowInventory = suspiciouslyLow,
            ),
        )

    @Test
    fun `each inventory visibility maps to the scope of the same name`() {
        mapOf(
            InstalledPackageVisibility.UNKNOWN to PackageVisibility.Scope.UNKNOWN,
            InstalledPackageVisibility.FULL to PackageVisibility.Scope.FULL,
            InstalledPackageVisibility.RESTRICTED to PackageVisibility.Scope.RESTRICTED,
        ).forEach { (visibility, scope) ->
            assertEquals(PackageVisibility(scope, 2, true), inventory(visibility, suspiciouslyLow = true).toPackageVisibility())
        }
    }

    @Test
    fun `an unreadable inventory is an unknown scope with nothing visible`() {
        val failure = PackageInventoryFailure(PackageInventoryFailureKind.PLATFORM_QUERY_FAILED, "denied")

        assertEquals(
            PackageVisibility(PackageVisibility.Scope.UNKNOWN, visiblePackageCount = 0, suspiciouslyLow = false),
            InstalledPackageInventoryResult.Unavailable(failure).toPackageVisibility(),
        )
    }
}
