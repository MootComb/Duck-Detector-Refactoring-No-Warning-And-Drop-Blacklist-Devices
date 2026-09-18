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

package com.eltavine.duckdetector.features.mount.data.repository

import com.eltavine.duckdetector.core.startup.preload.EarlyMountPreloadResult
import com.eltavine.duckdetector.features.mount.data.native.MountNativeBridge
import com.eltavine.duckdetector.features.mount.data.native.MountNativeSnapshot
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextMountMarker
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProbeManager
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProbeResult
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProbeState
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProcessSnapshot
import com.eltavine.duckdetector.features.mount.domain.MountMethodOutcome
import com.eltavine.duckdetector.features.mount.domain.MountStage
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextNamespaceAssessment
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextExposure
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MountZygoteNextRepositoryTest {

    @Test
    fun `isolated root marker becomes one direct mount danger signal`() = runBlocking {
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = readyResult(rootMarker()),
        ).scan()

        assertEquals(MountStage.READY, report.stage)
        assertTrue(report.zygoteNext.leakDetected)
        assertEquals(MountZygoteNextExposure.ROOT_MOUNT_EXPOSURE, report.zygoteNext.exposure)
        assertEquals(
            "ROOT_MOUNT_EXPOSURE",
            report.dangerFindings.single { it.id == "zygote_next_root_mount_exposure" }.value,
        )
        assertEquals(1, report.dangerSignalCount)
        assertEquals(
            MountMethodOutcome.DANGER,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `shared contrast without root marker remains clean`() = runBlocking {
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = readyResult(),
        ).scan()

        assertTrue(report.zygoteNext.contrastObserved)
        assertEquals(
            MountZygoteNextNamespaceAssessment.LIKELY_INIT,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(0, report.dangerSignalCount)
        assertEquals(0, report.warningSignalCount)
        assertEquals(
            MountMethodOutcome.CLEAN,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `missing mount id ordering is support instead of clean`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(rootMountId = 0L),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(
            MountMethodOutcome.SUPPORT,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `higher native mount id high-water does not override older root anchors`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(maximumMountId = 421L),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.LIKELY_INIT,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(
            MountMethodOutcome.CLEAN,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `short mount tables are unverified`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(mountCount = 7),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
    }

    @Test
    fun `shared native root without slave classic root is unverified`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(rootPropagation = "shared:1"),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(
            MountMethodOutcome.SUPPORT,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `shared and slave propagation is inconsistent`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(rootPropagation = "shared:2 master:1"),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.INCONSISTENT,
            report.zygoteNext.namespaceAssessment,
        )
    }

    @Test
    fun `fewer than three common anchors is unverified`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(
                    mountIdsByPoint = mapOf("/" to 240, "/dev" to 241),
                ),
                isolatedProcess = base.isolatedProcess.copy(
                    mountIdsByPoint = mapOf("/" to 24, "/dev" to 25),
                ),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
    }

    @Test
    fun `shared and master on isolated root is inconsistent`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(
                    rootPropagation = "shared:1 master:2",
                ),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.INCONSISTENT,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(
            MountMethodOutcome.WARNING,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `private isolated root is a namespace anomaly`() = runBlocking {
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = readyResult().copy(
                isolatedProcess = readyResult().isolatedProcess.copy(rootPropagation = "master:1"),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.PRIVATE_ANOMALY,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(1, report.warningSignalCount)
        assertEquals(
            MountMethodOutcome.WARNING,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `invalid isolated uid is unverified`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(uid = 10000),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
    }

    @Test
    fun `contradictory anchor chronology is inconsistent`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(
                    mountIdsByPoint = mapOf("/" to 250, "/dev" to 251, "/proc" to 252),
                ),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.INCONSISTENT,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(MountMethodOutcome.WARNING, report.methods.single {
            it.label == "Zygote next mount view"
        }.outcome)
    }

    @Test
    fun `matching namespace identities are unverified`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(mountNamespaceInode = 10L),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(
            MountMethodOutcome.SUPPORT,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `root marker remains dangerous when namespace coverage is unverified`() = runBlocking {
        val base = readyResult(rootMarker())
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(rootPropagation = "master:1"),
            ),
        ).scan()

        assertTrue(report.zygoteNext.leakDetected)
        assertEquals(
            MountMethodOutcome.DANGER,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `root marker in main process alone remains clean`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(markers = listOf(rootMarker())),
            ),
        ).scan()

        assertEquals(0, report.dangerSignalCount)
        assertTrue(report.zygoteNext.dangerousMarkers.isEmpty())
        assertEquals(
            MountMethodOutcome.CLEAN,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `zygote next evidence survives local native mount failure`() = runBlocking {
        val report = repository(
            nativeSnapshot = MountNativeSnapshot(available = false),
            zygoteNextResult = readyResult(rootMarker()),
        ).scan()

        assertEquals(MountStage.FAILED, report.stage)
        assertTrue(report.zygoteNext.leakDetected)
        assertEquals(1, report.dangerSignalCount)
        assertEquals(
            MountMethodOutcome.DANGER,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `zygote next evidence survives thrown local native mount failure`() = runBlocking {
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = readyResult(rootMarker()),
            nativeFailure = IllegalStateException("native bridge crashed"),
        ).scan()

        assertEquals(MountStage.FAILED, report.stage)
        assertTrue(report.zygoteNext.leakDetected)
        assertEquals(1, report.dangerSignalCount)
        assertEquals("native bridge crashed", report.errorMessage)
    }

    @Test
    fun `private namespace warning survives unavailable native snapshot`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = MountNativeSnapshot(available = false),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(rootPropagation = "master:1"),
            ),
        ).scan()

        assertEquals(MountStage.FAILED, report.stage)
        assertEquals(1, report.warningSignalCount)
        assertEquals(
            MountZygoteNextNamespaceAssessment.PRIVATE_ANOMALY.name,
            report.warningFindings.single { it.id == "zygote_next_namespace_anomaly" }.value,
        )
        assertEquals(
            MountMethodOutcome.WARNING,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `inconsistent namespace warning survives thrown native failure`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(rootPropagation = "shared:2 master:1"),
            ),
            nativeFailure = IllegalStateException("native bridge crashed"),
        ).scan()

        assertEquals(MountStage.FAILED, report.stage)
        assertEquals(1, report.warningSignalCount)
        assertEquals(
            MountZygoteNextNamespaceAssessment.INCONSISTENT.name,
            report.warningFindings.single { it.id == "zygote_next_namespace_anomaly" }.value,
        )
        assertEquals(
            MountMethodOutcome.WARNING,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    private fun repository(
        nativeSnapshot: MountNativeSnapshot,
        zygoteNextResult: ZygoteNextProbeResult,
        nativeFailure: Throwable? = null,
    ): MountRepository {
        return MountRepository(
            nativeBridge = object : MountNativeBridge() {
                override fun collectSnapshot(): MountNativeSnapshot {
                    nativeFailure?.let { throw it }
                    return nativeSnapshot
                }
            },
            preloadResultProvider = { EarlyMountPreloadResult.empty() },
            zygoteNextProbeManager = object : ZygoteNextProbeManager() {
                override suspend fun collect(): ZygoteNextProbeResult = zygoteNextResult
            },
        )
    }

    private fun readyResult(
        vararg markers: ZygoteNextMountMarker,
    ): ZygoteNextProbeResult {
        return ZygoteNextProbeResult(
            state = ZygoteNextProbeState.READY,
            sdkInt = 37,
            mainProcess = ZygoteNextProcessSnapshot(
                available = true,
                parentPid = 1,
                uid = 10000,
                mountNamespaceInode = 10,
                rootPropagation = "master:1",
                rootMountId = 240,
                minimumMountId = 220,
                maximumMountId = 420,
                mountCount = 100,
                mountIdsByPoint = mapOf(
                    "/" to 240,
                    "/dev" to 241,
                    "/proc" to 242,
                ),
            ),
            isolatedProcess = ZygoteNextProcessSnapshot(
                available = true,
                parentPid = 2,
                uid = 99020,
                mountNamespaceInode = 20,
                rootPropagation = "shared:1",
                rootMountId = 24,
                minimumMountId = 20,
                maximumMountId = 210,
                mountCount = 101,
                mountIdsByPoint = mapOf(
                    "/" to 24,
                    "/dev" to 25,
                    "/proc" to 26,
                ),
                markers = markers.toList(),
            ),
        )
    }

    private fun rootMarker(): ZygoteNextMountMarker {
        return ZygoteNextMountMarker(
            labels = listOf("KernelSU", "data/adb"),
            mountPoint = "/data/adb/modules/example",
            mountRoot = "/",
            fileSystemType = "ext4",
            source = "/dev/block/loop7",
            rawLine = "31 1 7:0 / /data/adb/modules/example rw - ext4 /dev/block/loop7 rw",
        )
    }

    private fun cleanSnapshot(): MountNativeSnapshot {
        return MountNativeSnapshot(
            available = true,
            mountsReadable = true,
            mountInfoReadable = true,
            mapsReadable = true,
            filesystemsReadable = true,
            statxSupported = true,
            permissionTotal = 4,
            permissionAccessible = 4,
            mountEntryCount = 30,
            mountInfoEntryCount = 30,
            mapLineCount = 100,
        )
    }
}
