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

import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility

/**
 * How much of the caller's own profile the identity probes could read. These decide whether an
 * empty result may read as clean: each gap is a way a present manager could go unseen.
 */
data class RootManagersCoverage(
    /**
     * Whether the caller's own launcher activity appeared in its own profile's launcher list; null
     * when the caller declares no launcher activity, so there is nothing to expect. False means the
     * list no longer satisfies the platform baseline, so its absences are not defensible.
     */
    val callerSelfObserved: Boolean? = null,
    /** PackageManager visibility for the caller-profile sweep, from the shared package-visibility policy. */
    val packageVisibility: InstalledPackageVisibility = InstalledPackageVisibility.UNKNOWN,
    val certificatesRead: Int = 0,
    val certificateReadFailures: Int = 0,
    val payloadDirectoriesRead: Int = 0,
    val payloadDirectoryFailures: Int = 0,
) {
    /** No certificate could be read although apps were checked, so the key anchor never had a chance. */
    val certificatesUnavailable: Boolean
        get() = certificatesRead == 0 && certificateReadFailures > 0
}
