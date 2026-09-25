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

package com.eltavine.duckdetector.features.customrom.data.repository

import java.util.concurrent.TimeUnit

fun interface CustomRomPropertyReader {
    fun read(name: String): String?
}

internal class DefaultCustomRomPropertyReader : CustomRomPropertyReader {

    override fun read(name: String): String? {
        readViaReflection(name)?.let { value ->
            return value
        }
        return readViaGetprop(name)
    }

    @Suppress("PrivateApi")
    private fun readViaReflection(name: String): String? {
        return runCatching {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            (method.invoke(null, name) as? String)?.trim()
        }.getOrNull()
    }

    private fun readViaGetprop(name: String): String? {
        var process: Process? = null
        return try {
            process = ProcessBuilder("getprop", name)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().use { it.readText().trim() }
            if (!process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                null
            } else {
                output.takeIf { it.isNotBlank() }
            }
        } catch (_: Exception) {
            null
        } finally {
            process?.destroy()
        }
    }

    private companion object {
        private const val PROCESS_TIMEOUT_SECONDS = 3L
    }
}
