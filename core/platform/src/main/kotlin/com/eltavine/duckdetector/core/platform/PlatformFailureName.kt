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
import android.os.Build
import android.os.DeadObjectException
import android.os.DeadSystemException
import android.os.OperationCanceledException
import android.os.ParcelFormatException
import android.os.RemoteException
import android.os.TransactionTooLargeException
import android.security.keystore.BackendBusyException
import android.security.keystore.KeyExpiredException
import android.security.keystore.KeyNotYetValidException
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.SecureKeyImportUnavailableException
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.system.ErrnoException
import android.util.AndroidException
import android.util.AndroidRuntimeException
import com.eltavine.duckdetector.core.evidence.FailureName

/**
 * [FailureName] extended with the Android platform failures that probes observe.
 *
 * Platform types are checked first, most specific first, because each of them is more specific than
 * the JVM type it extends; everything else is named by [FailureName]. Every type listed exists at
 * the minimum SDK, since a type check against a class missing on an older release is unsafe.
 *
 * Hidden platform failures such as `android.os.ServiceSpecificException` are not visible to the
 * compiler, so [HiddenPlatformFailure] recognises them first; an exact identity is more specific
 * than any type check. Keystore failures added after the minimum SDK are checked only on releases
 * that have them.
 */
public object PlatformFailureName {

    public fun of(failure: Throwable): String =
        HiddenPlatformFailure.nameOf(failure) ?: newerKeystoreFailureName(failure) ?: publicFailureName(failure)

    private fun newerKeystoreFailureName(failure: Throwable): String? = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            failure is android.security.KeyStoreException -> "KeyStoreException"
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && failure is BackendBusyException -> "BackendBusyException"
        else -> null
    }

    private fun publicFailureName(failure: Throwable): String = when (failure) {
        is DeadSystemException -> "DeadSystemException"
        is DeadObjectException -> "DeadObjectException"
        is TransactionTooLargeException -> "TransactionTooLargeException"
        is RemoteException -> "RemoteException"
        is PackageManager.NameNotFoundException -> "NameNotFoundException"
        is AndroidException -> "AndroidException"
        is ErrnoException -> "ErrnoException"
        is BadParcelableException -> "BadParcelableException"
        is AndroidRuntimeException -> "AndroidRuntimeException"
        is ParcelFormatException -> "ParcelFormatException"
        is OperationCanceledException -> "OperationCanceledException"
        is StrongBoxUnavailableException -> "StrongBoxUnavailableException"
        is SecureKeyImportUnavailableException -> "SecureKeyImportUnavailableException"
        is KeyPermanentlyInvalidatedException -> "KeyPermanentlyInvalidatedException"
        is UserNotAuthenticatedException -> "UserNotAuthenticatedException"
        is KeyExpiredException -> "KeyExpiredException"
        is KeyNotYetValidException -> "KeyNotYetValidException"
        else -> FailureName.of(failure)
    }

    public fun describe(failure: Throwable): String = FailureName.describe(failure, of(failure))

    public fun messageOrName(failure: Throwable): String = FailureName.messageOrName(failure, of(failure))
}
