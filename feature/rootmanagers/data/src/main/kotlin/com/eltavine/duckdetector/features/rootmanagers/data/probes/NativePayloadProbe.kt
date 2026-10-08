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

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import com.eltavine.duckdetector.core.platform.PlatformFailureName

internal sealed interface PayloadRead {
    /** The directory was observable; [present] lists the catalogued payloads found in it. */
    data class Read(val present: Set<String>) : PayloadRead

    /** A stat failed for a reason other than absence, so the payloads are unobserved. */
    data class Failed(val reason: String) : PayloadRead
}

/**
 * Looks for catalogued daemons in an app's extracted native library directory.
 *
 * The managers execute these binaries (`libksud.so`, `libapd.so`, `libmagisk.so`, ...) straight from
 * `nativeLibraryDir`, and their builds set `useLegacyPackaging` so the installer extracts them; a
 * rename of the package, label or classes leaves the file names in place. A stat needs only search
 * permission on the path, and `ENOENT` is a real absence while any other errno leaves the directory
 * unobserved rather than clean.
 */
internal class NativePayloadProbe(private val payloadNames: Set<String>) {

    fun read(nativeLibraryDir: String?): PayloadRead {
        val directory = nativeLibraryDir ?: return PayloadRead.Read(emptySet())
        val present = linkedSetOf<String>()
        for (name in payloadNames) {
            try {
                Os.stat("$directory/$name")
                present += name
            } catch (failure: ErrnoException) {
                if (failure.errno != OsConstants.ENOENT && failure.errno != OsConstants.ENOTDIR) {
                    return PayloadRead.Failed(PlatformFailureName.describe(failure))
                }
            }
        }
        return PayloadRead.Read(present)
    }
}
