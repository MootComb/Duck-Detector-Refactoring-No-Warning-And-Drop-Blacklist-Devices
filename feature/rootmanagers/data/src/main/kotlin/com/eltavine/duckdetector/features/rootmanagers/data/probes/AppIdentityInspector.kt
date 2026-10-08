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

package com.eltavine.duckdetector.features.rootmanagers.data.probes

import android.content.pm.ApplicationInfo
import com.eltavine.duckdetector.features.rootmanagers.domain.RootManagerCatalog

/**
 * Reads the manifest and file-system identity fields of one app for one scan.
 *
 * An app installed in several profiles shares one APK and one native library directory, so each
 * directory is stat-ed once per scan and the tallies count directories, not observations.
 */
internal class AppIdentityInspector(
    private val payloadProbe: NativePayloadProbe = NativePayloadProbe(
        RootManagerCatalog.signatures.flatMapTo(linkedSetOf()) { signature -> signature.nativePayloads },
    ),
) {

    private val payloadReads = mutableMapOf<String, PayloadRead>()

    val payloadDirectoriesRead: Int
        get() = payloadReads.values.count { read -> read is PayloadRead.Read }

    val payloadDirectoryFailures: Int
        get() = payloadReads.values.count { read -> read is PayloadRead.Failed }

    val zygotePreloadAvailable: Boolean
        get() = HiddenZygotePreloadField.available

    fun zygotePreloadName(info: ApplicationInfo?): String? = info?.let(HiddenZygotePreloadField::read)

    fun nativePayloads(info: ApplicationInfo?): Set<String> {
        val directory = info?.nativeLibraryDir ?: return emptySet()
        val read = payloadReads.getOrPut(directory) { payloadProbe.read(directory) }
        return (read as? PayloadRead.Read)?.present.orEmpty()
    }
}
