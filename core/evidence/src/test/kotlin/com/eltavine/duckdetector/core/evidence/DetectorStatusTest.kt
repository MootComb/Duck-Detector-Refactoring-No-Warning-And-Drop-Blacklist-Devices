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

package com.eltavine.duckdetector.core.evidence

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class DetectorStatusTest {

    @Test
    fun `factories produce the matching severity`() {
        assertEquals(DetectionSeverity.ALL_CLEAR, DetectorStatus.allClear().severity)
        assertEquals(DetectionSeverity.WARNING, DetectorStatus.warning().severity)
        assertEquals(DetectionSeverity.DANGER, DetectorStatus.danger().severity)
        assertNull(DetectorStatus.danger().infoKind)
        assertEquals(DetectorStatus(DetectionSeverity.INFO, InfoKind.ERROR), DetectorStatus.info(InfoKind.ERROR))
    }

    @Test
    fun `only info status may carry an info kind`() {
        DetectionSeverity.entries.filter { it != DetectionSeverity.INFO }.forEach { severity ->
            assertThrows(IllegalArgumentException::class.java) {
                DetectorStatus(severity, InfoKind.SUPPORT)
            }
        }
    }
}
