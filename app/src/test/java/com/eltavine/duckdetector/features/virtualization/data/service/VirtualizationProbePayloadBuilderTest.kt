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

package com.eltavine.duckdetector.features.virtualization.data.service

import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationNativeBridge
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationNativeFinding
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationNativeSnapshot
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteProfile
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteSnapshot
import com.eltavine.duckdetector.features.virtualization.data.probes.DexPathProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.UidIdentityProbeResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

@RunWith(Parameterized::class)
class VirtualizationProbePayloadBuilderTest(
    private val profile: VirtualizationRemoteProfile,
) {
    @Test
    fun `helper skips renderer and preserves diagnostic evidence`() {
        val environment = FakeEnvironment(profile)
        val nativeSnapshot = VirtualizationNativeSnapshot(
            available = true,
            mountNamespaceInode = "mnt:[4026531840]",
            apexMountKey = "21|8:1|/|/apex|ext4|/dev/block/dm-1",
            systemMountKey = "22|8:1|/|/system|ext4|/dev/block/dm-2",
            vendorMountKey = "23|8:1|/|/vendor|ext4|/dev/block/dm-3",
            findings = listOf(
                VirtualizationNativeFinding(
                    group = "TRANSLATION",
                    severity = "WARNING",
                    label = "Mapped translation library",
                    value = "libndk_translation.so",
                    detail = "/system/lib64/libndk_translation.so",
                ),
            ),
        )
        val bridge = RecordingNativeBridge(nativeSnapshot)

        val payload = VirtualizationProbePayloadBuilder.buildSnapshotPayload(
            environment = environment,
            profile = profile,
            nativeBridge = bridge,
        )
        val snapshot = VirtualizationRemoteSnapshot.parse(payload)

        // Assert outside the builder's runCatching so a swallowed failure cannot pass this test.
        assertEquals(listOf(false), bridge.rendererRequests)
        assertTrue(snapshot.available)
        assertTrue(snapshot.nativeAvailable)
        assertEquals(profile, snapshot.profile)
        assertEquals(environment.packageName, snapshot.packageName)
        assertEquals(environment.probeUidIdentity().uid, snapshot.uid)
        assertEquals(environment.probeUidIdentity().packagesForUid, snapshot.packagesForUid)
        assertEquals(environment.probeDexPath().classPathEntries, snapshot.classPathEntries)
        assertEquals(environment.codePath, snapshot.codePath)
        assertEquals(nativeSnapshot.mountNamespaceInode, snapshot.mountNamespaceInode)
        assertEquals(nativeSnapshot.apexMountKey, snapshot.apexMountKey)
        assertEquals(nativeSnapshot.systemMountKey, snapshot.systemMountKey)
        assertEquals(nativeSnapshot.vendorMountKey, snapshot.vendorMountKey)
        assertEquals(nativeSnapshot.findings, snapshot.findings)
        assertFalse(payload.lineSequence().any { it.startsWith("EGL_") })
        if (profile == VirtualizationRemoteProfile.ISOLATED) {
            assertEquals(0, environment.storageReads)
            assertEquals("", snapshot.filesDir)
            assertEquals("", snapshot.cacheDir)
        } else {
            assertEquals(2, environment.storageReads)
            assertEquals("/data/user/0/duck/files", snapshot.filesDir)
            assertEquals("/data/user/0/duck/cache", snapshot.cacheDir)
        }
    }

    @Test
    fun `native unavailable still preserves managed helper evidence without renderer retry`() {
        val bridge = RecordingNativeBridge(VirtualizationNativeSnapshot(available = false))

        val snapshot = VirtualizationRemoteSnapshot.parse(
            VirtualizationProbePayloadBuilder.buildSnapshotPayload(
                environment = FakeEnvironment(profile),
                profile = profile,
                nativeBridge = bridge,
            ),
        )

        assertEquals(listOf(false), bridge.rendererRequests)
        assertTrue(snapshot.available)
        assertFalse(snapshot.nativeAvailable)
        assertEquals(profile, snapshot.profile)
        assertEquals("com.eltavine.duckdetector", snapshot.packageName)
        assertEquals(listOf("/data/app/duck/base.apk"), snapshot.classPathEntries)
    }

    @Test
    fun `platform read failure stays inside payload error boundary`() {
        val bridge = RecordingNativeBridge(VirtualizationNativeSnapshot(available = true))
        val environment = object : FakeEnvironment(profile) {
            override val codePath: String get() = error("code path unavailable")
        }

        val snapshot = VirtualizationRemoteSnapshot.parse(
            VirtualizationProbePayloadBuilder.buildSnapshotPayload(
                environment = environment,
                profile = profile,
                nativeBridge = bridge,
            ),
        )

        assertEquals(listOf(false), bridge.rendererRequests)
        assertFalse(snapshot.available)
        assertFalse(snapshot.nativeAvailable)
        assertEquals(profile, snapshot.profile)
        assertEquals("code path unavailable", snapshot.errorDetail)
    }

    private class RecordingNativeBridge(
        private val snapshot: VirtualizationNativeSnapshot,
    ) : VirtualizationNativeBridge() {
        val rendererRequests = mutableListOf<Boolean>()

        override fun collectSnapshot(probeRenderer: Boolean): VirtualizationNativeSnapshot {
            rendererRequests += probeRenderer
            return snapshot
        }
    }

    private open class FakeEnvironment(
        private val profile: VirtualizationRemoteProfile,
    ) : VirtualizationProbePayloadBuilder.SnapshotEnvironment {
        var storageReads = 0
            private set

        override val packageName = "com.eltavine.duckdetector"
        override val codePath: String get() = "/data/app/duck/base.apk"
        override val filesDir: String get() = readStorage("files")
        override val cacheDir: String get() = readStorage("cache")

        override fun probeDexPath() = DexPathProbeResult(
            classPathEntries = listOf("/data/app/duck/base.apk"),
            sourceDir = "/data/app/duck/base.apk",
        )

        override fun probeUidIdentity() = UidIdentityProbeResult(
            uid = if (profile == VirtualizationRemoteProfile.ISOLATED) 99001 else 10123,
            packageName = packageName,
            packagesForUid = if (profile == VirtualizationRemoteProfile.ISOLATED) {
                emptyList()
            } else {
                listOf(packageName)
            },
        )

        private fun readStorage(directory: String): String {
            storageReads += 1
            check(profile != VirtualizationRemoteProfile.ISOLATED) {
                "Isolated helper must not access app-private storage"
            }
            return "/data/user/0/duck/$directory"
        }
    }

    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun profiles(): List<Array<VirtualizationRemoteProfile>> =
            VirtualizationRemoteProfile.entries.map { arrayOf(it) }
    }
}
