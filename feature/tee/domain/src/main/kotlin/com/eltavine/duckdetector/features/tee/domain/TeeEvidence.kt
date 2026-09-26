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

package com.eltavine.duckdetector.features.tee.domain

data class TeeEvidenceItem(
    val title: String,
    val body: String,
    val level: TeeSignalLevel,
    // 这是隐藏交互使用的原始复制文本；默认不展示在 UI 上，只在特定行位通过手势导出给人工审查。
    // Raw copy text for hidden interaction; it stays out of the visible UI and is only exported from specific rows through a gesture.
    val hiddenCopyText: String? = null,
    /** Set on the items that report a grant probe. */
    val grant: TeeGrantEvidence? = null,
    /** What the item is about, for the items the card gives an icon of their own. */
    val topic: TeeEvidenceTopic? = null,
)

/** The subjects of the evidence items the card gives an icon of their own. */
enum class TeeEvidenceTopic {
    TRUST_ROOT,
    RKP,
    CRL,
    VERIFIED_BOOT,
    BOOT_CONSISTENCY,
    DEVICE_IDS,
    USER_AUTH,
    APPLICATION,
    INDICATORS,
    TIMING,
    STRONGBOX,
    NATIVE,
    SOTER,
}

/** The grant probes whose failures the dashboard names. */
enum class TeeGrantProbe {
    SELF_DOMAIN,
    ISOLATED_DOMAIN,
    CALLER_BINDING,
}

/**
 * A grant probe's item as the dashboard's top finding reads it: the probe it reports and whether its
 * text names a key visibility divergence or a KEY_NOT_FOUND result.
 */
data class TeeGrantEvidence(
    val probe: TeeGrantProbe,
    val namesKeyVisibility: Boolean,
    val namesMissingKey: Boolean,
)

/** The sections of TEE evidence, in the order the card shows them; [title] heads each one. */
enum class TeeEvidenceSectionKind(val title: String) {
    TRUST("Trust"),
    ATTESTATION("Attestation"),
    CHECKS("Checks"),
}

data class TeeEvidenceSection(
    val kind: TeeEvidenceSectionKind,
    val items: List<TeeEvidenceItem>,
) {
    val title: String get() = kind.title
}
