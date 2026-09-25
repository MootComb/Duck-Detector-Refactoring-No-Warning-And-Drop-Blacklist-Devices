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

/**
 * Recognises platform failures whose types are hidden from the public SDK.
 *
 * Binder calls raise `android.os.ServiceSpecificException`, `ParcelableException` and
 * `DeadSystemRuntimeException`, none of which exist in android.jar, so no type check can name
 * them. Their runtime class name is the only identity they have, so it is compared here and
 * nowhere else, and reports receive a literal name rather than the class name itself.
 */
internal object HiddenPlatformFailure {

    fun nameOf(failure: Throwable): String? = when (failure.javaClass.name) {
        "android.os.ServiceSpecificException" -> "ServiceSpecificException"
        "android.os.ParcelableException" -> "ParcelableException"
        "android.os.DeadSystemRuntimeException" -> "DeadSystemRuntimeException"
        else -> null
    }
}
