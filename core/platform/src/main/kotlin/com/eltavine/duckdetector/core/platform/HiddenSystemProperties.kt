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
 * Reads `android.os.SystemProperties`, which is hidden from the public SDK.
 *
 * Probes compare this Java path with native and getprop reads, so it calls the hidden method
 * reflectively rather than a native equivalent. The two `get` overloads are separate methods and a
 * hook can target either one, so each is exposed as it is. Every read looks the method up again.
 */
public object HiddenSystemProperties {

    private const val CLASS_NAME = "android.os.SystemProperties"

    /** `SystemProperties.get(key)`, or the failure that prevented the read. */
    public fun read(key: String): Result<String?> = runCatching {
        systemProperties().getMethod("get", String::class.java).invoke(null, key) as? String
    }

    /** `SystemProperties.get(key, default)`, or the failure that prevented the read. */
    public fun read(key: String, default: String): Result<String?> = runCatching {
        systemProperties()
            .getMethod("get", String::class.java, String::class.java)
            .invoke(null, key, default) as? String
    }

    private fun systemProperties(): Class<*> = Class.forName(CLASS_NAME)
}
