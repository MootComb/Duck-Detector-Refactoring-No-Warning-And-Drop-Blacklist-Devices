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

import java.math.BigInteger
import org.gradle.api.GradleException
import org.json.JSONException
import org.json.JSONObject

internal const val TEE_CRL_GENERATED_ASSET_FILE_NAME = "tee_attestation_status.generated.json"
internal const val TEE_CRL_FALLBACK_ASSET_FILE_NAME = "tee_attestation_status.json"
internal const val TEE_CRL_STATUS_URL = "https://android.googleapis.com/attestation/status"

/** Parses an attestation status feed, failing unless it is a JSON object with `entries`. */
internal fun validatedStatusJson(json: String): JSONObject {
    val root = try {
        JSONObject(json)
    } catch (exception: JSONException) {
        throw GradleException("TEE CRL snapshot is not a JSON object.", exception)
    }
    if (root.optJSONObject("entries") == null) {
        throw GradleException("TEE CRL snapshot does not look like an attestation status feed.")
    }
    return root
}

/** The committed [fallback] feed with the entries only [remote] has added to it. */
internal fun mergeWithFallback(remote: String, fallback: String): String {
    val remoteRoot = validatedStatusJson(remote)
    val remoteEntries = remoteRoot.optJSONObject("entries")
        ?: throw GradleException("TEE CRL snapshot does not look like an attestation status feed.")
    val fallbackRoot = validatedStatusJson(fallback)
    val fallbackEntries = fallbackRoot.optJSONObject("entries")
        ?: throw GradleException("TEE CRL fallback asset does not look like an attestation status feed.")

    // The checked-in fallback asset is the repository-pinned revocation floor. Start from it,
    // then add remote-only entries so CI refresh strengthens the floor without weakening it.
    // 已入库的 fallback asset 是仓库固定的吊销下限；先以它为基线，再追加远端独有条目，确保 CI 刷新只增量强化。
    val remoteKeys = remoteEntries.keys()
    while (remoteKeys.hasNext()) {
        val key = remoteKeys.next()
        val remoteEntry = remoteEntries.getJSONObject(key)
        if (isLocalMassAbuseSerial(key) && remoteEntry.isRevokedOrSuspended()) {
            // 临时例外：构建增量真的拉到该序列号时，标记为远端来源，运行时不再降级成本地“大规模滥用”WARN。
            fallbackEntries.put(
                LOCAL_MASS_ABUSE_SERIAL,
                JSONObject(remoteEntry.toString()).put(DUCK_SOURCE_FIELD, DUCK_SOURCE_REMOTE),
            )
        } else if (fallbackEntries.has(key)) {
            continue
        } else {
            fallbackEntries.put(key, remoteEntry)
        }
    }
    return fallbackRoot.toString(2)
}

private fun isLocalMassAbuseSerial(key: String): Boolean {
    val normalized = key.lowercase().trimStart('0').ifBlank { "0" }
    return normalized == LOCAL_MASS_ABUSE_SERIAL ||
        runCatching {
            BigInteger(key).toString(16).lowercase() == LOCAL_MASS_ABUSE_SERIAL
        }.getOrDefault(false)
}

private fun JSONObject.isRevokedOrSuspended(): Boolean {
    return when (optString("status")) {
        "REVOKED", "SUSPENDED" -> true
        else -> false
    }
}

private const val LOCAL_MASS_ABUSE_SERIAL = "8616ef30679ed43cc2b43e3c97a2319e"
private const val DUCK_SOURCE_FIELD = "_duckDetectorSource"
private const val DUCK_SOURCE_REMOTE = "REMOTE"
