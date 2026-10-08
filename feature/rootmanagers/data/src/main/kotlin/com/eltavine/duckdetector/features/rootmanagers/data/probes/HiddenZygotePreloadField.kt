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

import android.content.pm.ApplicationInfo
import java.lang.reflect.Field
import org.lsposed.hiddenapibypass.HiddenApiBypass

/**
 * Reads the `@hide` field `ApplicationInfo.zygotePreloadName`, which `ApplicationInfo.writeToParcel`
 * carries across Binder but the SDK does not expose.
 *
 * `HiddenApiBypass.getInstanceFields` resolves the field from ART's field table without adding a
 * hidden-API exemption, so the process-wide policy that other detectors observe stays untouched.
 * Parsing every manifest through `getResourcesForApplication` would avoid the hidden field too, but
 * costs an AssetManager per app across the whole inventory.
 */
internal object HiddenZygotePreloadField {

    private const val FIELD_NAME = "zygotePreloadName"

    private val zygoteField: Field? by lazy {
        runCatching {
            HiddenApiBypass.getInstanceFields(ApplicationInfo::class.java).firstOrNull { it.name == FIELD_NAME }
        }.getOrNull()
    }

    /** False when the field could not be resolved, so the zygote anchor is missing, not absent. */
    val available: Boolean
        get() = zygoteField != null

    fun read(info: ApplicationInfo): String? {
        val resolved = zygoteField ?: return null
        return runCatching { resolved.get(info) as? String }.getOrNull()
    }
}
