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

import com.eltavine.duckdetector.features.tee.domain.TeeNetworkState

data class CrlStatusResult(
    val networkState: TeeNetworkState,
    val revokedCertificates: List<RevokedCertificate> = emptyList(),
)

data class RevokedCertificate(
    val serial: String,
    val reason: String,
    val evidenceKind: RevokedCertificateEvidenceKind = RevokedCertificateEvidenceKind.STANDARD_REVOCATION,
)

enum class RevokedCertificateEvidenceKind {
    STANDARD_REVOCATION,
    LOCAL_MASS_ABUSE,
}
