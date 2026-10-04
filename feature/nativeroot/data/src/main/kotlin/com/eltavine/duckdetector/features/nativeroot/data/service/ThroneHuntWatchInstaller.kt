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

import android.content.pm.ApplicationInfo
import android.os.Build
import com.eltavine.duckdetector.features.nativeroot.data.native.ThroneHuntWatchNativeBridge

// Owns the app_zygote side of the throne hunt oracle. It is intentionally framework-thin so both
// the ZygotePreload entry point and its unit test can share the same code path.
object ThroneHuntWatchInstaller {

    private const val PACKAGE_DIRECTORY_NOTE =
        "zygotePreloadName is required: only the app_zygote context may watch the package directory."

    @Volatile
    private var preloadedState: String? = null

    fun install(appInfo: ApplicationInfo, bridge: ThroneHuntWatchNativeBridge = ThroneHuntWatchNativeBridge()): ThroneHuntCarrierState =
        install(appInfo.sourceDir, Build.VERSION.SDK_INT, bridge)

    internal fun install(
        sourceDir: String?,
        sdkInt: Int,
        bridge: ThroneHuntWatchNativeBridge,
    ): ThroneHuntCarrierState {
        // The installer owns only the app_zygote/child boundary; it never owns native evidence.
        // 安装器只负责 app_zygote/child 边界，绝不拥有原生证据。

        // The watch is an inotify descriptor the carrier inherits through fork. Before every fork,
        // the zygote aborts on an open descriptor that is not a socket, regular file or character
        // device (frameworks/base core/jni/fd_utils.cpp, FileDescriptorInfo::CreateFromFd,
        // "Unsupported st_mode"; Android 11 through main). Only from Android 12 does AppZygoteInit
        // bracket doPreload with Zygote.markOpenedFilesBeforePreload and allowFilesOpenedByPreload,
        // which exempt what the preload opened; on Android 11 an open watch kills app_zygote.
        // 此 watch 是 carrier 经 fork 继承的 inotify 描述符。Android 11 的 app_zygote 不豁免
        // preload 打开的描述符，fork 时会因 "Unsupported st_mode" 中止，所以 Android 12 起才安装。
        if (sdkInt < Build.VERSION_CODES.S) {
            return ThroneHuntCarrierState(
                failureReason = "The inherited watch needs Android 12: an earlier app_zygote " +
                    "aborts every fork while its preload keeps an inotify descriptor open.",
                notes = listOf(PACKAGE_DIRECTORY_NOTE),
            )
        }

        if (sourceDir.isNullOrBlank()) {
            return ThroneHuntCarrierState(
                failureReason = "ApplicationInfo.sourceDir unavailable.",
            )
        }

        // /data/app is 0771 (other = --x) and inotify_add_watch runs inode_permission(MAY_READ),
        // so a watch on the root directory can never be granted to an app. The package directory
        // itself is 0755, which is why this vector targets the immediate child instead.
        val packageDirectory = sourceDir.substringBeforeLast('/', missingDelimiterValue = "")
        if (packageDirectory.isEmpty()) {
            return ThroneHuntCarrierState(
                failureReason = "Unable to derive the package directory from $sourceDir.",
            )
        }

        val watch = bridge.installWatch(packageDirectory)
        if (!watch.collection.isTrustworthy) {
            return ThroneHuntCarrierState(
                collection = watch.collection,
                failureReason = watch.collection.explain("Throne hunt watch collection failed"),
            )
        }
        return ThroneHuntCarrierState(
            collection = watch.collection,
            watchInstalled = watch.watchInstalled,
            watchDescriptor = watch.watchDescriptor,
            packageDirectory = watch.packageDirectory,
            failureReason = if (watch.watchInstalled) null else watch.detail,
            notes = listOf(PACKAGE_DIRECTORY_NOTE),
        )
    }

    fun publish(state: ThroneHuntCarrierState) {
        preloadedState = ThroneHuntCarrierPayloadCodec.encode(state)
    }

    fun consumeForCarrier(): String? {
        val raw = preloadedState
        preloadedState = null
        return raw
    }

    fun clearForTests() {
        preloadedState = null
    }
}
