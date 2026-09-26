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

package com.eltavine.duckdetector.capability.helperprocess.data

import android.app.Application
import android.content.Context
import android.os.Process

public data class UidIdentityObservation(
    val uid: Int = -1,
    val applicationUid: Int = -1,
    val packageName: String = "",
    val processName: String = "",
    val uidName: String = "",
    val packagesForUid: List<String> = emptyList(),
)

public open class UidIdentityCollector(
    private val context: Context? = null,
    private val uidProvider: () -> Int = { Process.myUid() },
    private val processNameProvider: () -> String = { Application.getProcessName() },
) {

    public open fun collect(): UidIdentityObservation? {
        val appContext = context?.applicationContext ?: return null
        val packageManager = appContext.packageManager
        val uid = runCatching(uidProvider).getOrDefault(-1)
        val applicationUid = runCatching { appContext.applicationInfo.uid }.getOrDefault(-1)
        val packageName = appContext.packageName
        val processName = runCatching(processNameProvider).getOrDefault("")
        val packagesForUid = runCatching {
            packageManager.getPackagesForUid(uid)?.toList().orEmpty()
        }.getOrDefault(emptyList())
            .map { it.orEmpty() }
            .filter { it.isNotBlank() }
            .distinct()
            .sorted()
        val uidName = runCatching { packageManager.getNameForUid(uid).orEmpty() }.getOrDefault("")

        return UidIdentityObservation(
            uid = uid,
            applicationUid = applicationUid,
            packageName = packageName,
            processName = processName,
            uidName = uidName,
            packagesForUid = packagesForUid,
        )
    }
}
