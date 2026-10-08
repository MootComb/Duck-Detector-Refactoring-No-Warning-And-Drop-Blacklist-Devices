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

/**
 * One root manager app the catalogue matched. This is a finding about an installed app, not a claim
 * that the device is rooted: an app hidden from both enumerations leaves no entry at all.
 */
data class RootManagerEntry(
    val family: RootManagerFamily,
    val packageName: String,
    val displayName: String,
    val profileUserId: Int,
    val componentClassName: String?,
    val applicationClassName: String?,
    val sourceDir: String?,
    val uid: Int?,
    val firstInstallTime: Long?,
    val anchors: Set<RootManagerAnchor>,
    val confidence: RootManagerConfidence,
    /** The family kernel's manager key this app is signed with, when the certificate matched. */
    val matchedCertificate: CertificateFingerprint? = null,
    val matchedPayloads: Set<String> = emptySet(),
    /** The manager disabled its launcher activity and is reachable only through app details. */
    val hidesLauncherIcon: Boolean = false,
) {
    val strong: Boolean
        get() = anchors.any { it.strong }

    /** An identified manager that also hid its launcher icon: presence plus concealment. */
    val concealed: Boolean
        get() = hidesLauncherIcon && confidence != RootManagerConfidence.LOW
}
