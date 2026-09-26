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

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/** Writes the TEE revocation snapshot the app bundles, refreshed from Google's feed when asked to. */
abstract class GenerateTeeCrlAssetTask : DefaultTask() {

    init {
        outputs.upToDateWhen {
            !refreshEnabled.get()
        }
    }

    @get:Input
    abstract val refreshEnabled: Property<Boolean>

    @get:Input
    abstract val endpointUrl: Property<String>

    @get:Input
    abstract val maxAttempts: Property<Int>

    @get:Input
    abstract val connectTimeoutMillis: Property<Int>

    @get:Input
    abstract val readTimeoutMillis: Property<Int>

    @get:Optional
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val fallbackAsset: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun generate() {
        val outputDir = outputDirectory.get().asFile
        val outputFile = outputDir.resolve(TEE_CRL_GENERATED_ASSET_FILE_NAME)
        outputDir.mkdirs()

        val refreshed = if (refreshEnabled.get()) fetchRemoteStatus() else null
        val fallback = fallbackAsset.orNull?.asFile?.takeIf { it.isFile }
        val json = refreshed?.let { remote -> fallback?.let { mergeWithFallback(remote, it.readText(Charsets.UTF_8)) } ?: remote }
            ?: readFallbackAsset()
        outputFile.writeText(json, Charsets.UTF_8)
    }

    private fun fetchRemoteStatus(): String? {
        val http = AssetHttpClient(connectTimeoutMillis.get(), readTimeoutMillis.get())
        val url = endpointUrl.get()
        val attempts = maxAttempts.get().coerceAtLeast(1)
        val outcome = fetchWithRetries(
            attempts = attempts,
            backoffMillis = { attempt -> (250L * attempt).coerceAtMost(1_250L) },
            warn = { attempt, reason -> logger.warn("TEE CRL snapshot fetch attempt $attempt/$attempts failed: $reason") },
        ) {
            http.text(url, mapOf("Accept" to "application/json")).also(::validatedStatusJson)
        }
        return when (outcome) {
            is FetchOutcome.Fetched -> outcome.value.also {
                logger.lifecycle("Fetched TEE CRL snapshot from $url on attempt ${outcome.attempt}/$attempts.")
            }
            is FetchOutcome.Failed -> null.also {
                logger.warn(
                    "TEE CRL snapshot refresh failed after $attempts attempts; falling back to local asset.",
                    outcome.lastFailure,
                )
            }
        }
    }

    private fun readFallbackAsset(): String {
        val fallback = fallbackAsset.orNull?.asFile
            ?: throw GradleException(
                "TEE CRL fallback asset is not configured. Expected " +
                    "src/main/assets/$TEE_CRL_FALLBACK_ASSET_FILE_NAME."
            )
        if (!fallback.isFile) {
            throw GradleException("TEE CRL fallback asset is missing: ${fallback.absolutePath}")
        }
        return fallback.readText(Charsets.UTF_8).also(::validatedStatusJson)
    }
}
