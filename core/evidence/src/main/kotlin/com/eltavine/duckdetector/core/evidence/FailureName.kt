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
import java.util.ConcurrentModificationException
import java.util.NoSuchElementException
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeoutException
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

/**
 * A failure type that states its own stable name.
 *
 * Release builds are minified, so the runtime class name of an app-defined exception is an
 * obfuscated identifier. An app exception that can reach a report implements this instead of
 * letting its name be read back from the class.
 */
public interface NamedFailure {
    public val failureName: String
}

/**
 * Names a failure for reports without reflecting on its class.
 *
 * The name is chosen by explicit type checks, most specific first, so it is always the failure's
 * own type or its nearest listed supertype and it never depends on the class name surviving
 * minification. A type outside the list is therefore named by an ancestor that is still true of it,
 * ending at `Throwable`, rather than by a guess.
 */
public object FailureName {

    public fun of(failure: Throwable): String = when (failure) {
        is NamedFailure -> failure.failureName
        is UnsatisfiedLinkError -> "UnsatisfiedLinkError"
        is NoClassDefFoundError -> "NoClassDefFoundError"
        is ExceptionInInitializerError -> "ExceptionInInitializerError"
        is LinkageError -> "LinkageError"
        is StackOverflowError -> "StackOverflowError"
        is OutOfMemoryError -> "OutOfMemoryError"
        is VirtualMachineError -> "VirtualMachineError"
        is AssertionError -> "AssertionError"
        is Error -> "Error"
        is ClassNotFoundException -> "ClassNotFoundException"
        is NoSuchMethodException -> "NoSuchMethodException"
        is NoSuchFieldException -> "NoSuchFieldException"
        is IllegalAccessException -> "IllegalAccessException"
        is InstantiationException -> "InstantiationException"
        is ReflectiveOperationException -> "ReflectiveOperationException"
        is CancellationException -> "CancellationException"
        is NumberFormatException -> "NumberFormatException"
        is IllegalArgumentException -> "IllegalArgumentException"
        is IllegalStateException -> "IllegalStateException"
        is UnsupportedOperationException -> "UnsupportedOperationException"
        is NullPointerException -> "NullPointerException"
        is ArrayIndexOutOfBoundsException -> "ArrayIndexOutOfBoundsException"
        is StringIndexOutOfBoundsException -> "StringIndexOutOfBoundsException"
        is IndexOutOfBoundsException -> "IndexOutOfBoundsException"
        is ClassCastException -> "ClassCastException"
        is ArithmeticException -> "ArithmeticException"
        is ConcurrentModificationException -> "ConcurrentModificationException"
        is NoSuchElementException -> "NoSuchElementException"
        is SecurityException -> "SecurityException"
        is ProviderException -> "ProviderException"
        is RuntimeException -> "RuntimeException"
        is FileNotFoundException -> "FileNotFoundException"
        is EOFException -> "EOFException"
        is SocketTimeoutException -> "SocketTimeoutException"
        is InterruptedIOException -> "InterruptedIOException"
        is UnknownHostException -> "UnknownHostException"
        is IOException -> "IOException"
        is CertificateExpiredException -> "CertificateExpiredException"
        is CertificateNotYetValidException -> "CertificateNotYetValidException"
        is CertificateParsingException -> "CertificateParsingException"
        is CertificateEncodingException -> "CertificateEncodingException"
        is CertificateException -> "CertificateException"
        is CertPathValidatorException -> "CertPathValidatorException"
        is KeyStoreException -> "KeyStoreException"
        is NoSuchAlgorithmException -> "NoSuchAlgorithmException"
        is InvalidKeyException -> "InvalidKeyException"
        is KeyException -> "KeyException"
        is UnrecoverableKeyException -> "UnrecoverableKeyException"
        is UnrecoverableEntryException -> "UnrecoverableEntryException"
        is SignatureException -> "SignatureException"
        is InvalidAlgorithmParameterException -> "InvalidAlgorithmParameterException"
        is AEADBadTagException -> "AEADBadTagException"
        is BadPaddingException -> "BadPaddingException"
        is IllegalBlockSizeException -> "IllegalBlockSizeException"
        is NoSuchPaddingException -> "NoSuchPaddingException"
        is GeneralSecurityException -> "GeneralSecurityException"
        is TimeoutException -> "TimeoutException"
        is ExecutionException -> "ExecutionException"
        is InterruptedException -> "InterruptedException"
        is Exception -> "Exception"
        else -> "Throwable"
    }

    /** The name alone, or `name: message` when the failure carries a non-blank message. */
    public fun describe(failure: Throwable): String {
        val message = failure.message?.takeIf(String::isNotBlank) ?: return of(failure)
        return "${of(failure)}: $message"
    }

    /** The non-blank message when there is one, otherwise the name. */
    public fun messageOrName(failure: Throwable): String {
        return failure.message?.takeIf(String::isNotBlank) ?: of(failure)
    }
}
