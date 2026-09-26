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

package com.eltavine.duckdetector.features.customrom.data.repository

import com.eltavine.duckdetector.features.customrom.data.native.CustomRomNativeSnapshot
import com.eltavine.duckdetector.features.customrom.data.rules.CustomRomCatalog
import com.eltavine.duckdetector.features.customrom.domain.CustomRomModificationFinding
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CustomRomModificationProbeTest {

    @Test
    fun `clean native snapshot produces no modification findings`() {
        val probe = CustomRomModificationProbe()

        val findings = probe.inspect(CustomRomNativeSnapshot())

        assertTrue(findings.isEmpty())
        assertEquals(
            CustomRomCatalog.modificationProperties.size,
            probe.checkedPropertyCount,
        )
    }

    @Test
    fun `native modification findings are forwarded unchanged`() {
        val finding = CustomRomModificationFinding(
            category = "Prop area",
            signal = "u:object_r:shell_prop:s0",
            summary = "Abnormal prop area",
            detail = "mode=644 uid=0 gid=0",
        )
        val probe = CustomRomModificationProbe()

        val findings = probe.inspect(
            CustomRomNativeSnapshot(
                available = true,
                modificationFindings = listOf(finding),
            ),
        )

        assertEquals(listOf(finding), findings)
    }
}
