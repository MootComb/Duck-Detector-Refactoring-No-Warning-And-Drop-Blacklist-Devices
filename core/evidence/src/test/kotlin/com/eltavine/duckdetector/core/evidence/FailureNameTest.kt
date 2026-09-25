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

import java.io.EOFException
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InterruptedIOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.ProviderException
import java.security.SignatureException
import java.security.UnrecoverableEntryException
import java.security.UnrecoverableKeyException
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateEncodingException
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.CertificateParsingException
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeoutException
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import org.junit.Assert.assertEquals
import org.junit.Test

class FailureNameTest {

    @Test
    fun `every listed type is named after itself`() {
        val expected = listOf(
            UnsatisfiedLinkError() to "UnsatisfiedLinkError",
            NoClassDefFoundError() to "NoClassDefFoundError",
            ExceptionInInitializerError() to "ExceptionInInitializerError",
            LinkageError() to "LinkageError",
            StackOverflowError() to "StackOverflowError",
            OutOfMemoryError() to "OutOfMemoryError",
            AssertionError() to "AssertionError",
            Error() to "Error",
            java.lang.reflect.InvocationTargetException(Throwable()) to "InvocationTargetException",
            ClassNotFoundException() to "ClassNotFoundException",
            NoSuchMethodException() to "NoSuchMethodException",
            NoSuchFieldException() to "NoSuchFieldException",
            IllegalAccessException() to "IllegalAccessException",
            InstantiationException() to "InstantiationException",
            ReflectiveOperationException() to "ReflectiveOperationException",
            CancellationException() to "CancellationException",
            NumberFormatException() to "NumberFormatException",
            IllegalArgumentException() to "IllegalArgumentException",
            IllegalStateException() to "IllegalStateException",
            UnsupportedOperationException() to "UnsupportedOperationException",
            NullPointerException() to "NullPointerException",
            ArrayIndexOutOfBoundsException() to "ArrayIndexOutOfBoundsException",
            StringIndexOutOfBoundsException() to "StringIndexOutOfBoundsException",
            IndexOutOfBoundsException() to "IndexOutOfBoundsException",
            ClassCastException() to "ClassCastException",
            ArithmeticException() to "ArithmeticException",
            ConcurrentModificationException() to "ConcurrentModificationException",
            NoSuchElementException() to "NoSuchElementException",
            SecurityException() to "SecurityException",
            ProviderException() to "ProviderException",
            java.lang.reflect.UndeclaredThrowableException(Throwable()) to "UndeclaredThrowableException",
            RuntimeException() to "RuntimeException",
            FileNotFoundException() to "FileNotFoundException",
            EOFException() to "EOFException",
            SocketTimeoutException() to "SocketTimeoutException",
            InterruptedIOException() to "InterruptedIOException",
            UnknownHostException() to "UnknownHostException",
            IOException() to "IOException",
            CertificateExpiredException() to "CertificateExpiredException",
            CertificateNotYetValidException() to "CertificateNotYetValidException",
            CertificateParsingException() to "CertificateParsingException",
            CertificateEncodingException() to "CertificateEncodingException",
            CertificateException() to "CertificateException",
            CertPathValidatorException() to "CertPathValidatorException",
            KeyStoreException() to "KeyStoreException",
            NoSuchAlgorithmException() to "NoSuchAlgorithmException",
            InvalidKeyException() to "InvalidKeyException",
            KeyException() to "KeyException",
            UnrecoverableKeyException() to "UnrecoverableKeyException",
            UnrecoverableEntryException() to "UnrecoverableEntryException",
            SignatureException() to "SignatureException",
            InvalidAlgorithmParameterException() to "InvalidAlgorithmParameterException",
            AEADBadTagException() to "AEADBadTagException",
            BadPaddingException() to "BadPaddingException",
            IllegalBlockSizeException() to "IllegalBlockSizeException",
            NoSuchPaddingException() to "NoSuchPaddingException",
            GeneralSecurityException() to "GeneralSecurityException",
            TimeoutException() to "TimeoutException",
            ExecutionException(Throwable()) to "ExecutionException",
            InterruptedException() to "InterruptedException",
            Exception() to "Exception",
            Throwable() to "Throwable",
        )

        expected.forEach { (failure, name) ->
            assertEquals(name, FailureName.of(failure))
        }
    }

    @Test
    fun `an unlisted type is named by its nearest listed supertype`() {
        class TransientStateFailure : IllegalStateException()
        class VendorCheckedFailure : Exception()
        class VendorVmFailure : VirtualMachineError()
        class BareThrowable : Throwable()

        assertEquals("IllegalStateException", FailureName.of(TransientStateFailure()))
        assertEquals("Exception", FailureName.of(VendorCheckedFailure()))
        assertEquals("VirtualMachineError", FailureName.of(VendorVmFailure()))
        assertEquals("Throwable", FailureName.of(BareThrowable()))
    }

    @Test
    fun `a named failure states its own name ahead of any supertype`() {
        class ContractFailure : IllegalArgumentException(), NamedFailure {
            override val failureName: String = "ContractFailure"
        }

        assertEquals("ContractFailure", FailureName.of(ContractFailure()))
    }

    @Test
    fun `describe joins the name and a non-blank message`() {
        assertEquals("IllegalStateException: probe aborted", FailureName.describe(IllegalStateException("probe aborted")))
        assertEquals("UnsatisfiedLinkError", FailureName.describe(UnsatisfiedLinkError()))
        assertEquals("IllegalArgumentException", FailureName.describe(IllegalArgumentException("   ")))
    }

    @Test
    fun `messageOrName prefers a non-blank message`() {
        assertEquals("dlopen failed", FailureName.messageOrName(UnsatisfiedLinkError("dlopen failed")))
        assertEquals("UnsatisfiedLinkError", FailureName.messageOrName(UnsatisfiedLinkError()))
        assertEquals("SecurityException", FailureName.messageOrName(SecurityException(" ")))
    }
}
