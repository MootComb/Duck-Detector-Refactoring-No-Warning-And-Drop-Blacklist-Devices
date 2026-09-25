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

package com.eltavine.duckdetector.capability.packageinventory.domain

// Build.VERSION_CODES.R. This module has no Android SDK on its classpath to reference it from.
private const val ANDROID_11_API_LEVEL = 30

/** The visibility guarantee provided by PackageManager, not a guess based on list size. */
public enum class InstalledPackageVisibility {
    UNKNOWN,
    FULL,
    RESTRICTED,
}

public data class PackageVisibilityEnvironment(
    val deviceSdk: Int,
    val targetSdk: Int,
    val queryAllPackagesRequested: Boolean,
)

/**
 * Pure policy for Android's package-visibility compatibility contract.
 *
 * Android 11 enables FILTER_APPLICATION_QUERY for callers targeting API 30 or newer. A caller
 * that requests the normal QUERY_ALL_PACKAGES permission is exempt. Counts deliberately do not
 * participate: automatically visible packages can make a filtered result arbitrarily large.
 */
public object InstalledPackageVisibilityPolicy {

    public fun evaluate(
        environment: PackageVisibilityEnvironment,
        callerPackageObserved: Boolean,
    ): InstalledPackageVisibility {
        // A successful PackageManager inventory must include the caller. Missing it means the
        // observed response no longer satisfies the platform baseline, so absence claims are not
        // defensible even if the manifest requests broad visibility.
        if (!callerPackageObserved) {
            return InstalledPackageVisibility.UNKNOWN
        }
        if (environment.deviceSdk < ANDROID_11_API_LEVEL ||
            environment.targetSdk < ANDROID_11_API_LEVEL
        ) {
            return InstalledPackageVisibility.FULL
        }
        return if (environment.queryAllPackagesRequested) {
            InstalledPackageVisibility.FULL
        } else {
            InstalledPackageVisibility.RESTRICTED
        }
    }
}

public object InstalledPackageInventoryAnomalyPolicy {

    public const val SUSPICIOUSLY_LOW_VISIBLE_PACKAGE_COUNT: Int = 60

    public fun isSuspiciouslyLow(
        visibility: InstalledPackageVisibility,
        installedPackageCount: Int,
        sdkInt: Int,
    ): Boolean {
        return sdkInt >= ANDROID_11_API_LEVEL &&
                visibility == InstalledPackageVisibility.FULL &&
                installedPackageCount < SUSPICIOUSLY_LOW_VISIBLE_PACKAGE_COUNT
    }
}
