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

package com.eltavine.duckdetector.features.nativeroot.detector

import android.content.pm.ApplicationInfo
import com.eltavine.duckdetector.features.nativeroot.data.service.ThroneHuntWatchInstaller

/**
 * The part of the Native Root detector that must run in the app zygote.
 *
 * KernelSU's pkg_observer reacts to a /data/system/packages.list rewrite by running
 * track_throne -> search_manager("/data/app", 2), which opens and iterates every package
 * directory inode. Watching this package's own directory from app_zygote is what makes that
 * kernel-side traversal observable, so the watch is installed there rather than in the child.
 * Without the app zygote preload the throne-hunt carrier reports its collection as failed, because
 * the dedicated app_zygote preload state is unavailable.
 */
public object NativeRootZygotePreload {
    public fun installThroneHuntWatch(appInfo: ApplicationInfo) {
        ThroneHuntWatchInstaller.publish(ThroneHuntWatchInstaller.install(appInfo))
    }
}
