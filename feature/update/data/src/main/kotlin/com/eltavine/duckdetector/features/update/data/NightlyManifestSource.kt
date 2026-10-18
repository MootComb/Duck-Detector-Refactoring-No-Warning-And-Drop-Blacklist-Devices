/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.eltavine.duckdetector.features.update.data

import com.eltavine.duckdetector.features.update.domain.NightlyUpdateApk

/** Independently checks the selected APK against its own official release manifest. */
internal class NightlyManifestSource(private val client: UpdateHttpClient) {
    fun forApk(apk: NightlyUpdateApk): NightlyUpdateApk {
        val tag = NightlyReleasePaths.tagFor(apk.downloadUrl, apk.name)
        val manifest = UpdateManifestParser().parse(client.get(NightlyReleasePaths.manifestUrl(tag), "application/json"))
        require(NightlyReleasePaths.tagFor(manifest.apk.downloadUrl, manifest.apk.name) == tag) {
            "Official manifest points at another release"
        }
        return manifest.apk
    }
}
