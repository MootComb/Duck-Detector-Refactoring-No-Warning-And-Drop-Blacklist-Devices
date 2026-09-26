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

import android.os.IBinder

/**
 * Calls `android.os.ServiceManager`, which is hidden from the public SDK.
 *
 * Probes ask the service manager directly for registrations that the public APIs never expose.
 * Every call looks the method up again and returns the failure instead of throwing, so each probe
 * keeps its own scope for how far a failure reaches.
 */
public object HiddenServiceManager {

    private const val CLASS_NAME = "android.os.ServiceManager"

    /** `ServiceManager.getService(name)`, or the failure that prevented the call. */
    public fun getService(name: String): Result<IBinder?> = runCatching {
        serviceManager().getMethod("getService", String::class.java).invoke(null, name) as? IBinder
    }

    /** The names `ServiceManager.listServices()` returned, or the failure that prevented the call. */
    public fun listServices(): Result<List<String>> = runCatching {
        (serviceManager().getMethod("listServices").invoke(null) as? Array<*>)
            ?.filterIsInstance<String>()
            .orEmpty()
    }

    private fun serviceManager(): Class<*> = Class.forName(CLASS_NAME)
}
