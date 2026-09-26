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

import com.eltavine.duckdetector.capability.attestation.data.AttestationSnapshot
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import java.nio.file.Files

internal fun withManifest(xml: String, block: (String) -> Unit) {
    val dir = Files.createTempDirectory("duck_vintf").toFile()
    try {
        val manifest = dir.resolve("manifest.xml")
        manifest.writeText(xml)
        block(manifest.absolutePath)
    } finally {
        dir.deleteRecursively()
    }
}

internal fun withManifestDirectory(files: Map<String, String>, block: (String) -> Unit) {
    val dir = Files.createTempDirectory("duck_vintf_dir").toFile()
    try {
        files.forEach { (name, content) -> dir.resolve(name).writeText(content) }
        block(dir.absolutePath)
    } finally {
        dir.deleteRecursively()
    }
}

internal fun vendorApiLevelReader(level: Int): VendorApiLevelReader = VendorApiLevelReader {
    VendorApiLevelResult(level, "test vendor API level=$level")
}

internal fun keyMintDeclaration(aidlVersion: Int): VintfKeyMintVersionDeclaration {
    return VintfKeyMintVersionDeclaration(
        family = VintfKeyMintVersionFamily.KEYMINT_AIDL,
        sourcePath = "/test/manifest.xml",
        format = "aidl",
        halName = "android.hardware.security.keymint",
        interfaceName = "IKeyMintDevice",
        instance = "default",
        vintfVersion = aidlVersion.toString(),
        expectedKeymasterVersion = aidlVersion * 100,
        expectedAttestationVersion = aidlVersion * 100,
    )
}

internal fun snapshot(attestationVersion: Int?, keymasterVersion: Int?): AttestationSnapshot {
    return AttestationSnapshot(
        tier = TeeTier.TEE,
        attestationVersion = attestationVersion,
        keymasterVersion = keymasterVersion,
        attestationTier = TeeTier.TEE,
        keymasterTier = TeeTier.TEE,
        challengeVerified = true,
        challengeSummary = "ok",
        rootOfTrust = null,
        osVersion = null,
        osPatchLevel = null,
        vendorPatchLevel = null,
        bootPatchLevel = null,
        rawCertificates = emptyList(),
        displayCertificates = emptyList(),
    )
}
