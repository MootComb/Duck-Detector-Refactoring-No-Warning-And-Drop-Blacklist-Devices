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

package com.eltavine.duckdetector.features.nativeroot.data.service

import com.eltavine.duckdetector.core.native.NativeCollectionOutcome
import com.eltavine.duckdetector.core.native.NativeLibraryHandle
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector
import com.eltavine.duckdetector.features.nativeroot.data.native.ThroneHuntWatchNativeBridge
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ThroneHuntWatchInstallerTest {

    private val library = RecordingLibrary()
    private val bridge = ThroneHuntWatchNativeBridge(collector = NativeSnapshotCollector(library))

    @Test
    fun `before Android 12 no watch descriptor is opened in app_zygote`() {
        val state = ThroneHuntWatchInstaller.install(SOURCE_DIR, sdkInt = 30, bridge = bridge)

        assertFalse("the native watch must not be reached", library.queried)
        assertFalse(state.watchInstalled)
        assertEquals(-1, state.watchDescriptor)
        assertTrue(state.failureReason.orEmpty().contains("Android 12"))
        // An unsupported release is not a denied watch, which the card reports differently.
        assertFalse(state.watchDenied)
    }

    @Test
    fun `from Android 12 the watch is requested from the native bridge`() {
        val state = ThroneHuntWatchInstaller.install(SOURCE_DIR, sdkInt = 31, bridge = bridge)

        assertTrue(library.queried)
        assertFalse(state.watchInstalled)
        assertEquals(NativeCollectionOutcome.LIBRARY_UNAVAILABLE, state.collection.outcome)
    }

    private class RecordingLibrary : NativeLibraryHandle {
        var queried = false

        override val isLoaded: Boolean
            get() {
                queried = true
                return false
            }

        override val loadFailureDetail: String = "not loaded in unit tests"
    }

    private companion object {
        const val SOURCE_DIR = "/data/app/~~abc==/com.eltavine.duckdetector-def==/base.apk"
    }
}
