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

import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageInventoryResult
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.core.evidence.ContractValue

/**
 * How much of the installed package list this process can see. It bounds every detector that reads
 * the package inventory, so a host can tell a clean inventory from one that package visibility
 * filtering hides, and decide whether to request `QUERY_ALL_PACKAGES`.
 */
@ContractValue
public class PackageVisibility(
    public val scope: Scope,
    public val visiblePackageCount: Int,
    /** Whether fewer packages are visible than any Android release installs, which suggests hiding. */
    public val suspiciouslyLow: Boolean,
) {
    public enum class Scope {
        /** The inventory could not be read, so the scope is not known. */
        UNKNOWN,

        /** Every installed package is visible. */
        FULL,

        /** Package visibility filtering applies to this process. */
        RESTRICTED,
    }
}

internal fun InstalledPackageInventoryResult.toPackageVisibility(): PackageVisibility {
    val inventory = (this as? InstalledPackageInventoryResult.Available)?.inventory
        ?: return PackageVisibility(PackageVisibility.Scope.UNKNOWN, visiblePackageCount = 0, suspiciouslyLow = false)
    val scope = when (inventory.visibility) {
        InstalledPackageVisibility.UNKNOWN -> PackageVisibility.Scope.UNKNOWN
        InstalledPackageVisibility.FULL -> PackageVisibility.Scope.FULL
        InstalledPackageVisibility.RESTRICTED -> PackageVisibility.Scope.RESTRICTED
    }
    return PackageVisibility(scope, inventory.visiblePackageCount, inventory.suspiciouslyLowInventory)
}
