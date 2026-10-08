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

/** Which platform path produced an [ObservedApp]; the two differ in what they can read. */
enum class ObservationSource {
    /** A launcher activity `LauncherApps` returned for some accessible profile. */
    LAUNCHER_APPS,

    /** An installed application `PackageManager` returned for the caller's own profile. */
    PACKAGE_MANAGER,
}

/**
 * One installed app as the enumeration observed it, filled in without interpretation.
 *
 * The signing certificates and native payloads are only read in the caller's own profile, because
 * `PackageManager` answers for the calling user alone; an app seen only through another profile's
 * launcher list carries the manifest fields and leaves those two empty.
 */
data class ObservedApp(
    /** The profile the app lives in: 0 for the owner, the profile's user id otherwise. */
    val profileUserId: Int,
    val packageName: String,
    val source: ObservationSource,
    /** The launcher activity class, or the synthetic app-details activity of a hidden icon. */
    val componentClassName: String? = null,
    val applicationClassName: String? = null,
    val label: String? = null,
    val zygotePreloadName: String? = null,
    val signingCertificates: List<CertificateFingerprint> = emptyList(),
    /** File names of catalogued payloads present in the app's native library directory. */
    val nativePayloads: Set<String> = emptySet(),
    /**
     * True when the launcher entry is the synthetic `android.app.AppDetailsActivity` that
     * `LauncherAppsService` injects for an app whose own launcher activity was disabled at runtime.
     */
    val hidesLauncherIcon: Boolean = false,
    val sourceDir: String? = null,
    val uid: Int? = null,
    val firstInstallTime: Long? = null,
)
