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

package com.eltavine.duckdetector.features.customrom.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CustomRomNativeBridgeTest {

    @Test
    fun `policy modification and symbol traces are parsed from native snapshot`() {
        val bridge = CustomRomNativeBridge()

        val snapshot = bridge.parse(
            """
            AVAILABLE=1
            PROPAREA_AVAILABLE=1
            PROPAREA_CONTEXTS=4
            PROPAREA_AREA_ANOMALIES=1
            PROPAREA_ITEM_ANOMALIES=2
            SYMBOL_AVAILABLE=1
            MODIFICATION=Prop area|u:object_r:shell_prop:s0|Abnormal prop area|mode=644 uid=0 gid=0
            POLICY=LineageOS|/vendor/etc/selinux/vendor_sepolicy.cil|hal_lineage|3
            SYMBOL=Native symbol trace|ANetworkSession::threadLoopEv|/apex/com.android.media/lib64/libstagefright.so
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.propertyAreaAvailable)
        assertEquals(4, snapshot.propertyAreaContextCount)
        assertEquals(1, snapshot.propertyAreaAnomalyCount)
        assertEquals(2, snapshot.propertyAreaItemCount)
        assertEquals(2, snapshot.propertyAreaItemAnomalyCount)
        assertTrue(snapshot.symbolScanAvailable)
        assertEquals(1, snapshot.modificationFindings.size)
        assertEquals("Prop area", snapshot.modificationFindings.single().category)
        assertEquals("u:object_r:shell_prop:s0", snapshot.modificationFindings.single().signal)
        assertEquals(1, snapshot.policyFindings.size)
        assertEquals("hal_lineage", snapshot.policyFindings.single().signal)
        assertEquals("/vendor/etc/selinux/vendor_sepolicy.cil (3 hits)", snapshot.policyFindings.single().detail)
        assertEquals(1, snapshot.symbolFindings.size)
        assertEquals("Native symbol trace", snapshot.symbolFindings.single().romName)
        assertEquals("ANetworkSession::threadLoopEv", snapshot.symbolFindings.single().signal)
        assertEquals("/apex/com.android.media/lib64/libstagefright.so", snapshot.symbolFindings.single().detail)
    }

    @Test
    fun `legacy property area count keys still parse as anomaly counts`() {
        val bridge = CustomRomNativeBridge()

        val snapshot = bridge.parse(
            """
            AVAILABLE=1
            PROPAREA_AVAILABLE=1
            PROPAREA_CONTEXTS=3
            PROPAREA_AREA_COUNT=1
            PROPAREA_ITEM_COUNT=2
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.propertyAreaAvailable)
        assertEquals(3, snapshot.propertyAreaContextCount)
        assertEquals(1, snapshot.propertyAreaAnomalyCount)
        assertEquals(2, snapshot.propertyAreaItemAnomalyCount)
    }
}
