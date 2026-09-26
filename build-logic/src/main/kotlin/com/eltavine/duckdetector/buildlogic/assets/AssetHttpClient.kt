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

package com.eltavine.duckdetector.buildlogic.assets

import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * GET requests for the tasks that refresh committed assets, on the JDK's HTTP client. Redirects are
 * followed except from HTTPS to HTTP, as `HttpURLConnection` followed them, and a status outside 2xx
 * fails with the status and the start of the body.
 */
internal class AssetHttpClient(connectTimeoutMillis: Int, private val readTimeoutMillis: Int) {

    private val client: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofMillis(connectTimeoutMillis.toLong()))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build()

    fun text(url: String, headers: Map<String, String>): String = String(bytes(url, headers), Charsets.UTF_8)

    fun bytes(url: String, headers: Map<String, String>): ByteArray {
        val request = HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofMillis(readTimeoutMillis.toLong()))
            .apply { headers.forEach { (name, value) -> header(name, value) } }
            .GET()
            .build()
        val response = client.send(request, HttpResponse.BodyHandlers.ofByteArray())
        val status = response.statusCode()
        if (status !in 200..299) {
            throw IOException("HTTP $status ${String(response.body(), Charsets.UTF_8).take(ERROR_BODY_PREVIEW)}".trim())
        }
        return response.body()
    }

    private companion object {
        const val ERROR_BODY_PREVIEW = 120
    }
}
