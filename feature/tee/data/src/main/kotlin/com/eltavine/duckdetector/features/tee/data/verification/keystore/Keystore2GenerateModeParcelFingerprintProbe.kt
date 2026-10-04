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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

data class Keystore2GenerateModeParcelFingerprintResult(
    val executed: Boolean,
    val available: Boolean = false,
    val authorizationCount: Int? = null,
    val modificationTimeMs: Long? = null,
    val anomaly: GenerateKeyReplyAnomaly? = null,
    val rawPrefix: String? = null,
    val diagnosticCopyText: String? = null,
    val detail: String,
)

class Keystore2GenerateModeParcelFingerprintProbe(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
    private val parser: GenerateKeyReplyParcelParser = GenerateKeyReplyParcelParser(),
) {

    fun inspect(useStrongBox: Boolean = false): Keystore2GenerateModeParcelFingerprintResult {
        val capture = binderClient.captureGenerateKeyReply(useStrongBox)
        if (!capture.available) {
            return Keystore2GenerateModeParcelFingerprintResult(
                executed = false,
                available = false,
                diagnosticCopyText = GenerateKeyParcelDiagnosticFormatter.format(
                    rawRequest = capture.rawRequest,
                    rawReply = capture.rawReply,
                    parseResult = null,
                    captureDetail = capture.detail,
                ),
                rawPrefix = capture.rawPrefix,
                detail = capture.detail,
            )
        }

        val rawReply = capture.rawReply
        if (rawReply == null) {
            return Keystore2GenerateModeParcelFingerprintResult(
                executed = true,
                available = false,
                diagnosticCopyText = GenerateKeyParcelDiagnosticFormatter.format(
                    rawRequest = capture.rawRequest,
                    rawReply = capture.rawReply,
                    parseResult = null,
                    captureDetail = capture.detail,
                ),
                rawPrefix = capture.rawPrefix,
                detail = capture.detail,
            )
        }

        val parsed = parser.parse(rawReply = rawReply, rawPrefix = capture.rawPrefix)
        val diagnosticCopyText = GenerateKeyParcelDiagnosticFormatter.format(
            rawRequest = capture.rawRequest,
            rawReply = rawReply,
            parseResult = parsed,
            captureDetail = capture.detail,
        )
        if (!parsed.parseSucceeded) {
            return Keystore2GenerateModeParcelFingerprintResult(
                executed = true,
                available = false,
                diagnosticCopyText = diagnosticCopyText,
                rawPrefix = parsed.rawPrefix,
                detail = parsed.detail,
            )
        }

        return Keystore2GenerateModeParcelFingerprintResult(
            executed = true,
            available = true,
            authorizationCount = parsed.authorizations.size,
            modificationTimeMs = parsed.modificationTimeMs,
            anomaly = parsed.anomaly,
            rawPrefix = parsed.rawPrefix,
            diagnosticCopyText = diagnosticCopyText,
            detail = parsed.detail,
        )
    }
}
