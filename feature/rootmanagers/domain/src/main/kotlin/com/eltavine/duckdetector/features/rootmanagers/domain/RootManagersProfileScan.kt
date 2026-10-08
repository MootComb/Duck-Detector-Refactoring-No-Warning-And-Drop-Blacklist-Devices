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

package com.eltavine.duckdetector.features.rootmanagers.domain

enum class ProfileScanState {
    /** The profile returned launcher activities, so a clean result means it was searched. */
    SEARCHED,

    /**
     * The profile returned no launcher activity at all. A usable profile always lists some, and
     * `LauncherApps.getActivityList` also returns an empty list when the service refuses an
     * inaccessible profile, so an empty profile counts as not observed rather than as clean.
     */
    EMPTY,

    /** The platform threw `SecurityException` for this profile. */
    DENIED,
}

/**
 * What the enumeration saw in one profile. It keeps counts only: the identities of unmatched apps
 * are the user's app inventory and leave the scan, the report and the clipboard untouched.
 */
data class RootManagersProfileScan(
    val profileUserId: Int,
    val state: ProfileScanState,
    val launcherActivitiesSeen: Int = 0,
    /** Distinct apps whose identity was checked here, launcher entries and PackageManager sweep alike. */
    val appsChecked: Int = 0,
)
