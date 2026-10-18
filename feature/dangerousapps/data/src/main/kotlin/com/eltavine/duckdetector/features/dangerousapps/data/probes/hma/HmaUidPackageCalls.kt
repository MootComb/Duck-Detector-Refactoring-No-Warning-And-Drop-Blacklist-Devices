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

package com.eltavine.duckdetector.features.dangerousapps.data.probes.hma

import com.eltavine.duckdetector.core.platform.HiddenServiceManager
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckState
import org.lsposed.hiddenapibypass.HiddenApiBypass
import java.lang.reflect.InvocationTargetException
import kotlin.coroutines.cancellation.CancellationException

/** Each operation reads the package service, bypassing the public Java clients' caches. */
internal interface HmaUidPackageCalls {
    fun packages(uid: Int): List<String>
    fun permission(uid: Int, permission: String): Boolean
}

internal class HmaPackageManagerBinder(
    private val resolve: () -> Any = ::resolvePackageService,
    private val invoke: (Any, String, Array<out Any?>) -> Any? = { service, method, args ->
        HiddenApiBypass.invoke(service.javaClass, service, method, *args)
    },
) : HmaUidPackageCalls {
    // One proxy belongs to one scan. No process-wide exemption or cache setting is changed.
    private val service by lazy(resolve)

    override fun packages(uid: Int): List<String> {
        val value = invoke(service, "getPackagesForUid", arrayOf(uid)) ?: return emptyList()
        check(value is Array<*>) { "Invalid UID association response" }
        return value.map {
            check(it is String && it.isNotBlank()) { "Invalid UID association entry" }
            it
        }
    }

    override fun permission(uid: Int, permission: String): Boolean =
        when (invoke(service, "checkUidPermission", arrayOf<Any?>(permission, uid))) {
            0 -> true
            -1 -> false
            else -> error("Invalid UID permission response")
        }
}

private fun resolvePackageService(): Any {
    val binder = HiddenServiceManager.getService("package").getOrThrow()
        ?: error("Package service is unavailable")
    val stub = Class.forName("android.content.pm.IPackageManager\$Stub")
    return HiddenApiBypass.invoke(stub, null, "asInterface", binder)
        ?: error("Package service interface is unavailable")
}

internal data class HmaUidCallFailure(val state: HmaCheckState, val detail: String) {
    companion object {
        fun from(failure: Throwable): HmaUidCallFailure {
            var cause = failure
            while (cause is InvocationTargetException && cause.targetException !== cause) {
                cause = cause.targetException
            }
            if (cause is CancellationException) throw cause
            return HmaUidCallFailure(
                if (cause is SecurityException) HmaCheckState.PERMISSION_LIMITED else HmaCheckState.UNAVAILABLE,
                PlatformFailureName.describe(cause),
            )
        }
    }
}
