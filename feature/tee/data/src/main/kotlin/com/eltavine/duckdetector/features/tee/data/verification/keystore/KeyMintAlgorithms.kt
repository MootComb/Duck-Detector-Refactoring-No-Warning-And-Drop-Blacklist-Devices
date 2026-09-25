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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

internal const val SIGNATURE_ECDSA_SHA256 = "SHA256withECDSA"

internal const val CIPHER_RSA_PKCS1 = "RSA/ECB/PKCS1Padding"

internal const val CIPHER_RSA_OAEP_SHA1_MGF1 = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"

internal const val CIPHER_RSA_OAEP_SHA256_MGF1 = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

internal const val KEYMINT_TAG_RSA_OAEP_MGF_DIGEST = 0x200000CB
