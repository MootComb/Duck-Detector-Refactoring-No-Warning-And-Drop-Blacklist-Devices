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

package com.eltavine.duckdetector.features.tee.data.verification.crl

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

fun interface CrlNetworkStatusProvider {
    fun isNetworkAvailable(): Boolean
}

fun interface CrlFeedFetcher {
    @Throws(Exception::class)
    fun fetch(): String
}

fun interface CrlEmbeddedStatusProvider {
    @Throws(Exception::class)
    fun load(): String
}

internal class AndroidCrlNetworkStatusProvider(
    private val context: Context,
) : CrlNetworkStatusProvider {

    override fun isNetworkAvailable(): Boolean {
        val connectivityManager =
            context.getSystemService(ConnectivityManager::class.java) ?: return false
        val activeNetwork = connectivityManager.activeNetwork ?: return false
        val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork) ?: return false
        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }
}

internal class HttpCrlFeedFetcher : CrlFeedFetcher {

    override fun fetch(): String {
        val connection = URL(STATUS_URL).openConnection() as HttpURLConnection
        return try {
            connection.requestMethod = "GET"
            connection.connectTimeout = NETWORK_TIMEOUT_MS
            connection.readTimeout = NETWORK_TIMEOUT_MS
            connection.instanceFollowRedirects = true
            connection.setRequestProperty("Accept", "application/json")

            val statusCode = connection.responseCode
            val body =
                (if (statusCode in 200..299) connection.inputStream else connection.errorStream)
                    ?.bufferedReader()
                    ?.use { reader -> reader.readText() }
                    .orEmpty()

            if (statusCode !in 200..299) {
                throw HttpStatusException(
                    statusCode = statusCode,
                    statusMessage = connection.responseMessage,
                    responseSnippet = body.take(200).takeIf { it.isNotBlank() },
                )
            }

            body
        } finally {
            connection.disconnect()
        }
    }

    private companion object {
        private const val STATUS_URL = "https://android.googleapis.com/attestation/status"
        private const val NETWORK_TIMEOUT_MS = 5_000
    }
}

internal class AssetsCrlEmbeddedStatusProvider(
    private val context: Context,
) : CrlEmbeddedStatusProvider {

    override fun load(): String {
        val assetManager = context.assets
        val assetName = if (assetManager.list("").orEmpty().contains(GENERATED_ASSET_FILE_NAME)) {
            GENERATED_ASSET_FILE_NAME
        } else {
            FALLBACK_ASSET_FILE_NAME
        }
        return assetManager.open(assetName).bufferedReader(Charsets.UTF_8).use { reader ->
            reader.readText()
        }
    }

    private companion object {
        private const val GENERATED_ASSET_FILE_NAME = "tee_attestation_status.generated.json"
        private const val FALLBACK_ASSET_FILE_NAME = "tee_attestation_status.json"
    }
}

internal class HttpStatusException(
    val statusCode: Int,
    val statusMessage: String?,
    val responseSnippet: String?,
) : IOException("HTTP $statusCode ${statusMessage.orEmpty()}".trim())
