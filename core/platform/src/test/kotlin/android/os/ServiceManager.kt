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

package android.os

// Stand-in for the hidden ServiceManager, which android.jar does not contain.
class ServiceManager {
    companion object {
        var services: Map<String, IBinder> = emptyMap()
        var listed: Array<Any?> = emptyArray()

        @JvmStatic
        fun getService(name: String): IBinder? = services[name]

        @JvmStatic
        fun listServices(): Array<Any?> = listed
    }
}
