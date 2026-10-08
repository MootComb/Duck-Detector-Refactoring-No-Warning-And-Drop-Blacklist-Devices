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

package com.eltavine.duckdetector.features.rootmanagers.data.probes

import org.junit.Assert.assertEquals
import org.junit.Test

class SigningCertificatesTest {

    @Test
    fun `the fingerprint is the DER length and lowercase SHA-256 hex the kernel compares`() {
        val fingerprint = SigningCertificates.fingerprint("abc".toByteArray())

        assertEquals(3, fingerprint.sizeBytes)
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", fingerprint.sha256)
    }

    @Test
    fun `bytes above 0x7f keep two lowercase hex digits`() {
        val fingerprint = SigningCertificates.fingerprint(ByteArray(0))

        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", fingerprint.sha256)
        assertEquals(64, SigningCertificates.fingerprint(byteArrayOf(0xff.toByte(), 0x80.toByte())).sha256.length)
    }
}
