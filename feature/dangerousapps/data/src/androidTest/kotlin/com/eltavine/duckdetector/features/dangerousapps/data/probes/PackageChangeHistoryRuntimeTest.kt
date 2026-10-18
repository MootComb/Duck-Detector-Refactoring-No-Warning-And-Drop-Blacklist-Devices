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

package com.eltavine.duckdetector.features.dangerousapps.data.probes

import android.content.pm.PackageManager
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsCatalog
import com.eltavine.duckdetector.features.dangerousapps.domain.PackageChangeHistoryState
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/** Optional expectations let a fixture install/remove/reboot sequence exercise the real framework. */
@RunWith(AndroidJUnit4::class)
class PackageChangeHistoryRuntimeTest {
    @Test fun queryCurrentBoot() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val args = InstrumentationRegistry.getArguments()
        val expectedPackage = args.getString("historyPackage")
        val targets = if (expectedPackage == null) DangerousAppsCatalog.targets else listOf(
            DangerousAppsCatalog.targets.single { it.packageName == expectedPackage },
        )
        val probe = PackageChangeHistoryProbe(context)
        repeat(2) {
            val result = probe.run(targets)
            assertEquals(PackageChangeHistoryState.AVAILABLE, result.state)
            args.getString("expectHistoryMatch")?.let { expected ->
                assertEquals(expected.toBooleanStrict(), result.matchedTargets.any {
                    it.packageName == expectedPackage
                })
            }
            Log.i("PackageChangeHistoryTest",
                "state=${result.state} sequence=${result.sequenceNumber} matches=${result.matchedTargets.map { it.packageName }}")
        }
        if (expectedPackage != null) {
            args.getString("expectPackageVisible")?.let { expected ->
                val visible = try {
                    @Suppress("DEPRECATION")
                    context.packageManager.getPackageInfo(expectedPackage, 0)
                    true
                } catch (_: PackageManager.NameNotFoundException) {
                    false
                }
                assertEquals(expected.toBooleanStrict(), visible)
            }
        }
    }
}
