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

package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelResult
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel

internal fun timingSideChannelSkipSignature(
    result: TimingSideChannelResult,
): TimingSideChannelSkipSignature? {
    // 这里只识别 skip 场景：一旦 measurementAvailable=true，说明 timing probe 已经进入样本比较语义，不能再被静态栈特征改写成 patch-mode。
    // Only recognize skip scenarios here: once measurementAvailable=true, the probe is already in sample-comparison semantics and static stacks must not rewrite it into patch-mode.
    if (result.measurementAvailable) {
        return null
    }
    val payload = result.stackCopyPayload
        .replace("\r\n", "\n")
        .takeIf { it.isNotBlank() && it != "null" }
        ?: return null
    return when {
        // TEE Simulator 家族目前有两套稳定静态签名：
        // 1) tees-rs 样例里的 generateKey + deleteKey 组合；2) tees 样例里的 code -75 + legacy-db 组合。
        // timing 行仍然沿用 patch-mode 文案，生成模式结论则在 generateModeAnomalyState 里复用第二套组合。
        // The TEE Simulator family currently has two stable static signatures:
        // 1) the generateKey + deleteKey combination from the tees-rs sample; 2) the code -75 + legacy-db combination from the tees sample.
        // The timing row keeps the patch-mode wording, while generate-mode matching reuses the second combination in generateModeAnomalyState.
        payload.containsAllNeedles(
            listOf(
                "android.os.ServiceSpecificException (code -49)",
                "at android.os.Parcel.createExceptionOrNull",
                "at android.os.Parcel.createException",
                "at ${'$'}Proxy7.generateKey(Unknown Source)",
                "Caused by:",
                "0: Legacy database is empty.",
                "1: Error::Rc(r#KEY_NOT_FOUND) (code 7)",
                "at ${'$'}Proxy5.deleteKey(Unknown Source)",
            ),
        ) || payload.matchesTeeSimulatorLegacyDbSignature() -> TimingSideChannelSkipSignature.TEE_SIMULATOR_PATCH_MODE

        // 组合命中 ts 样例里的 getKeyEntry 失败栈后，再提升为 Tricky-Store Patch Mode。
        // Elevate to Tricky-Store Patch Mode only after the full getKeyEntry failure combination from the ts sample is present.
        payload.containsAllNeedles(
            listOf(
                "Caused by: android.os.ServiceSpecificException (code 7)",
                "at android.os.Parcel.createException",
                "at android.os.Parcel.readException",
                "at ${'$'}Proxy5.getKeyEntry(Unknown Source)",
            ),
        ) -> TimingSideChannelSkipSignature.TRICKY_STORE_PATCH_MODE

        // 如果所有更具体的 patch/generate 组合都没有命中，但仍然看到 Parcel 三连异常，就保留一个 warning 级别的私有 binder 兜底信号。
        // If no more specific patch/generate signature matches, keep a warning-level private-binder fallback when the Parcel exception trio is still present.
        // Every ServiceSpecificException that crosses binder carries this trio, and a device without
        // FEATURE_KEYSTORE_APP_ATTEST_KEY is expected to refuse the probe's ATTEST_KEY, so the
        // fallback only applies where that key should have been accepted.
        result.appAttestKeyAdvertised && payload.containsAllNeedles(
            listOf(
                "at android.os.Parcel.createExceptionOrNull",
                "at android.os.Parcel.createException",
                "at android.os.Parcel.readException",
            ),
        ) -> TimingSideChannelSkipSignature.PRIVATE_BINDER_EXCEPTION

        else -> null
    }
}

internal enum class TimingSideChannelSkipSignature(
    val summary: String,
    val rowLabel: String,
    val level: TeeSignalLevel,
) {
    // 这些标签只在“测量未建立”的 skip 语义里生效，用来把静态栈特征提升成可见的 patch-mode 结论。
    // These labels only apply to skip semantics where measurement never started, promoting static stack signatures into visible patch-mode outcomes.
    TRICKY_STORE_PATCH_MODE(
        // 用户可见文案统一收敛成通用的“已知 keystore 拦截模块”，避免把具体模块/模式名暴露给最终展示层。
        // User-visible wording is intentionally collapsed into a generic known keystore-interception module
        // message so the UI does not expose module-specific labels. The match is a stack signature, so the
        // copy names what matched rather than judging the module's intent.
        summary = "Keystore errors during timing skip matched a known keystore-interception module.",
        rowLabel = "Matched a known keystore-interception module",
        level = TeeSignalLevel.FAIL,
    ),
    TEE_SIMULATOR_PATCH_MODE(
        summary = "Keystore errors during timing skip matched a known keystore-interception module.",
        rowLabel = "Matched a known keystore-interception module",
        level = TeeSignalLevel.FAIL,
    ),
    PRIVATE_BINDER_EXCEPTION(
        summary = "Captured private binder exception during timing skip.",
        rowLabel = "Captured private binder exception during timing skip",
        level = TeeSignalLevel.WARN,
    ),
}

private fun String.containsAllNeedles(needles: List<String>): Boolean {
    return needles.all { contains(it) }
}

private fun String.matchesTeeSimulatorLegacyDbSignature(): Boolean {
    return containsAllNeedles(
        listOf(
            "android.os.ServiceSpecificException (code -75)",
            "at android.os.Parcel.createExceptionOrNull",
            "at android.os.Parcel.createException",
            "at android.os.Parcel.readException",
            "Caused by:",
            "0: Legacy database is empty.",
            "1: Error::Rc(r#KEY_NOT_FOUND) (code 7)",
        ),
    )
}

internal fun generateModeAnomalyState(artifacts: TeeScanArtifacts): GenerateModeAnomalyState {
    val result = artifacts.generateModeParcelFingerprint
    val timingPayload = artifacts.timingSideChannel.stackCopyPayload
        .replace("\r\n", "\n")
        .takeIf { it.isNotBlank() && it != "null" }
    return when {
        result.matched -> GenerateModeAnomalyState.MATCHED
        // tees 样例里的 code -75 + legacy-db 组合落在 timing skip payload 里时，语义上也属于 TEE Simulator 生成链路命中。
        // When the tees code -75 + legacy-db combination lands in a timing skip payload, it also counts as a TEE Simulator generate-path hit.
        timingPayload?.matchesTeeSimulatorLegacyDbSignature() == true -> GenerateModeAnomalyState.MATCHED
        result.available -> GenerateModeAnomalyState.CLEAN
        else -> GenerateModeAnomalyState.UNAVAILABLE
    }
}

internal enum class GenerateModeAnomalyState {
    MATCHED,
    CLEAN,
    UNAVAILABLE,
}

internal fun keyMintRuntimeIdentityMismatch(artifacts: TeeScanArtifacts): Boolean {
    val attestationVersion = artifacts.vintfKeyMintVersion.attestationVersion ?: return false
    val keymasterVersion = artifacts.vintfKeyMintVersion.keymasterVersion ?: return false
    return attestationVersion >= 100 &&
        keymasterVersion >= 100 &&
        attestationVersion != keymasterVersion
}
