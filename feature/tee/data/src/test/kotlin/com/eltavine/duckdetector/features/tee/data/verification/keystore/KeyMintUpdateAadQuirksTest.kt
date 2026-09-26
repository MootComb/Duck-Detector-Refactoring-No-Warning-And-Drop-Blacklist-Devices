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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyMintUpdateAadQuirksTest {

    private fun identity(
        manufacturer: String,
        brand: String = manufacturer,
        hardware: String = "",
        roHardware: String? = null,
    ) = KeyMintVendorIdentity(manufacturer, brand, hardware, roHardware)

    @Test
    fun `samsung by manufacturer or brand accepts updateAad`() {
        assertTrue(updateAadAcceptanceExpected(identity("samsung")))
        assertTrue(updateAadAcceptanceExpected(identity(manufacturer = "Unknown", brand = "Samsung")))
    }

    @Test
    fun `xiaomi family accepts updateAad only on mediatek`() {
        assertTrue(updateAadAcceptanceExpected(identity("Xiaomi", roHardware = "mt6789")))
        assertTrue(updateAadAcceptanceExpected(identity(manufacturer = "Xiaomi", brand = "Redmi", hardware = "MT6877")))
        assertFalse(updateAadAcceptanceExpected(identity("Xiaomi", roHardware = "qcom", hardware = "qcom")))
    }

    @Test
    fun `other vendors are not expected to accept updateAad`() {
        assertFalse(updateAadAcceptanceExpected(identity("Google", hardware = "tensor")))
        assertFalse(updateAadAcceptanceExpected(identity("OnePlus", roHardware = "mt6983")))
    }
}
