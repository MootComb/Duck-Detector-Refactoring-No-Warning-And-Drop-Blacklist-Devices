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

import android.content.pm.PackageManager
import android.os.BadParcelableException
import android.os.DeadObjectException
import android.os.DeadSystemException
import android.os.OperationCanceledException
import android.os.ParcelFormatException
import android.os.RemoteException
import android.os.TransactionTooLargeException
import android.security.keystore.KeyExpiredException
import android.security.keystore.KeyNotYetValidException
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.SecureKeyImportUnavailableException
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.system.ErrnoException
import android.util.AndroidException
import android.util.AndroidRuntimeException
import com.eltavine.duckdetector.core.evidence.NamedFailure
import org.junit.Assert.assertEquals
import org.junit.Test

class PlatformFailureNameTest {

    @Test
    fun `every listed platform type is named after itself`() {
        val expected = listOf(
            DeadSystemException() to "DeadSystemException",
            DeadObjectException() to "DeadObjectException",
            TransactionTooLargeException() to "TransactionTooLargeException",
            RemoteException() to "RemoteException",
            PackageManager.NameNotFoundException() to "NameNotFoundException",
            AndroidException() to "AndroidException",
            ErrnoException("open", 13) to "ErrnoException",
            BadParcelableException("bad") to "BadParcelableException",
            AndroidRuntimeException() to "AndroidRuntimeException",
            ParcelFormatException() to "ParcelFormatException",
            OperationCanceledException() to "OperationCanceledException",
            StrongBoxUnavailableException() to "StrongBoxUnavailableException",
            SecureKeyImportUnavailableException() to "SecureKeyImportUnavailableException",
            KeyPermanentlyInvalidatedException() to "KeyPermanentlyInvalidatedException",
            UserNotAuthenticatedException() to "UserNotAuthenticatedException",
            KeyExpiredException() to "KeyExpiredException",
            KeyNotYetValidException() to "KeyNotYetValidException",
        )

        expected.forEach { (failure, name) ->
            assertEquals(name, PlatformFailureName.of(failure))
        }
    }

    @Test
    fun `other failures are named by the JVM namer`() {
        class ContractFailure : IllegalArgumentException(), NamedFailure {
            override val failureName: String = "ContractFailure"
        }

        assertEquals("IllegalStateException", PlatformFailureName.of(IllegalStateException()))
        assertEquals("FileNotFoundException", PlatformFailureName.of(java.io.FileNotFoundException()))
        assertEquals("ContractFailure", PlatformFailureName.of(ContractFailure()))
    }

    @Test
    fun `hidden platform failures are named from their runtime identity`() {
        assertEquals("ServiceSpecificException", PlatformFailureName.of(android.os.ServiceSpecificException(7)))
        assertEquals("ParcelableException", PlatformFailureName.of(android.os.ParcelableException(Throwable())))
        assertEquals("DeadSystemRuntimeException", PlatformFailureName.of(android.os.DeadSystemRuntimeException()))
        assertEquals(
            "ServiceSpecificException: No key found",
            PlatformFailureName.describe(android.os.ServiceSpecificException(7, "No key found")),
        )
    }

    @Test
    fun `hidden identity is the full class name, not the simple name`() {
        class ServiceSpecificException : RuntimeException()

        assertEquals("RuntimeException", PlatformFailureName.of(ServiceSpecificException()))
    }

    @Test
    fun `wording follows the shared rule`() {
        assertEquals("RemoteException", PlatformFailureName.describe(RemoteException()))
        assertEquals("IllegalStateException: gone", PlatformFailureName.describe(IllegalStateException("gone")))
        assertEquals("ErrnoException", PlatformFailureName.messageOrName(ErrnoException("stat", 2)))
    }
}
