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

import com.eltavine.duckdetector.capability.earlypreload.data.EarlyMountPreloadResult
import com.eltavine.duckdetector.features.mount.data.native.MountNativeBridge
import com.eltavine.duckdetector.features.mount.data.native.MountNativeSnapshot
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextMountMarker
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProbeManager
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProbeResult
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProbeState
import com.eltavine.duckdetector.features.mount.data.zygotenext.ZygoteNextProcessSnapshot

internal fun repository(
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

internal fun readyResult(
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

internal fun rootMarker(): ZygoteNextMountMarker {
    return ZygoteNextMountMarker(
        labels = listOf("KernelSU", "data/adb"),
        mountPoint = "/data/adb/modules/example",
        mountRoot = "/",
        fileSystemType = "ext4",
        source = "/dev/block/loop7",
        rawLine = "31 1 7:0 / /data/adb/modules/example rw - ext4 /dev/block/loop7 rw",
    )
}

internal fun cleanSnapshot(): MountNativeSnapshot {
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
