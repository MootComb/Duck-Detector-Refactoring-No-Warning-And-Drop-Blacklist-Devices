/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.rootmanagers.domain

/**
 * The value a KernelSU-family kernel uses to recognise its manager app.
 *
 * `kernel/manager/apk_sign.c` reads the first certificate of the first signer in the APK's v2
 * signature block and accepts the app as manager only when that certificate's byte length and
 * SHA-256 equal the build's `EXPECTED_SIZE` and `EXPECTED_HASH`. Matching both values is the same
 * test the kernel applies, so it survives a renamed package, label or class: none of those change
 * the signing key, and a manager re-signed with another key is no longer the manager that kernel
 * trusts.
 */
data class CertificateFingerprint(
    val sizeBytes: Int,
    /** Lowercase hex SHA-256 of the DER certificate bytes. */
    val sha256: String,
)
