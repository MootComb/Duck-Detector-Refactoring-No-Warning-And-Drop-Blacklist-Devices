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

// Stand-in for the hidden SystemProperties, which android.jar does not contain. It records which
// overload was called so the tests can tell them apart.
class SystemProperties {
    companion object {
        var values: Map<String, String> = emptyMap()
        var lastOverload: String? = null

        @JvmStatic
        fun get(key: String): String {
            lastOverload = "get(key)"
            return values[key].orEmpty()
        }

        @JvmStatic
        fun get(key: String, def: String): String {
            lastOverload = "get(key, def)"
            return values[key] ?: def
        }
    }
}
