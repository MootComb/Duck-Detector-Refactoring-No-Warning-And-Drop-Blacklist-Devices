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

package com.eltavine.duckdetector.core.platform

import android.os.ParcelableException
import android.os.ServiceSpecificException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HiddenPlatformFailureTest {

    @Test
    fun `a service specific failure exposes its error code`() {
        val failure = ServiceSpecificException(7, "No key found")

        assertTrue(HiddenPlatformFailure.isServiceSpecific(failure))
        assertEquals(7, HiddenPlatformFailure.serviceSpecificErrorCode(failure))
    }

    @Test
    fun `a parcelable failure is recognised`() {
        assertTrue(HiddenPlatformFailure.isParcelable(ParcelableException(Throwable())))
        assertFalse(HiddenPlatformFailure.isServiceSpecific(ParcelableException(Throwable())))
    }

    @Test
    fun `other failures are neither and carry no error code`() {
        val failure = IllegalStateException("gone")

        assertFalse(HiddenPlatformFailure.isServiceSpecific(failure))
        assertFalse(HiddenPlatformFailure.isParcelable(failure))
        assertNull(HiddenPlatformFailure.serviceSpecificErrorCode(failure))
    }

    @Test
    fun `recognition needs the full class name`() {
        class ServiceSpecificException(@JvmField val errorCode: Int) : RuntimeException()

        assertFalse(HiddenPlatformFailure.isServiceSpecific(ServiceSpecificException(7)))
        assertNull(HiddenPlatformFailure.serviceSpecificErrorCode(ServiceSpecificException(7)))
    }
}
