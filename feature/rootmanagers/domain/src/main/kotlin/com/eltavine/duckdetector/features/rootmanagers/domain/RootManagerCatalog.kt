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
 * The installed-app identity of every mainstream root manager family.
 *
 * Signing certificates are the defaults of each family kernel's `kernel/Kbuild` or
 * `kernel/manager/manager_sign.h` (`EXPECTED_SIZE` in bytes, `EXPECTED_HASH` as the certificate
 * SHA-256). Payloads and manifest names come from each manager's build files and manifest at the
 * revisions listed in `EVIDENCE.md`.
 */
object RootManagerCatalog {

    // 0x033b. tiann/KernelSU kernel/Kbuild KSU_EXPECTED_SIZE/HASH; MKSU (5ec1cff/KernelSU) defaults to it too.
    private val kernelSuOfficialCert = CertificateFingerprint(
        sizeBytes = 827,
        sha256 = "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6",
    )

    // 0x375. Listed as KOWX712/KernelSU in BakaSU's manager_sign.h; that fork keeps the me.weishu.kernelsu namespace.
    private val kernelSuKowx712Cert = CertificateFingerprint(
        sizeBytes = 885,
        sha256 = "484fcba6e6c43b1fb09700633bf2fb4758f13cb0b2f4457b80d075084b26c588",
    )

    // 0x3e6. KernelSU-Next/KernelSU-Next kernel/Kbuild KSU_NEXT_MANAGER_SIZE/HASH.
    private val kernelSuNextCert = CertificateFingerprint(
        sizeBytes = 998,
        sha256 = "79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7",
    )

    // 0x35c. SukiSU-Ultra/SukiSU-Ultra kernel/Kbuild KSU_EXPECTED_SIZE/HASH.
    private val sukiSuCert = CertificateFingerprint(
        sizeBytes = 860,
        sha256 = "947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef",
    )

    // 0x377. Baka-SU/BakaSU kernel/manager/manager_sign.h EXPECTED_SIZE_BAKASU/HASH_BAKASU.
    private val bakaSuCert = CertificateFingerprint(
        sizeBytes = 887,
        sha256 = "d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64",
    )

    private const val KSUD = "libksud.so"
    private const val MAGICA_PRELOAD = ".magica.AppZygotePreload"
    private const val KERNEL_SU_APPLICATION = ".KernelSUApplication"
    private const val UI_MAIN_ACTIVITY = ".ui.MainActivity"

    val signatures: List<RootManagerSignature> = listOf(
        RootManagerSignature(
            family = RootManagerFamily.KERNEL_SU,
            // MKSU now defaults to me.weishu.kernelsu; io.github.a13e300.mksu stays in step with Native Root's list.
            packageNames = setOf("me.weishu.kernelsu", "io.github.a13e300.mksu"),
            codeNamespaces = setOf("me.weishu.kernelsu"),
            applicationClassSuffixes = setOf(KERNEL_SU_APPLICATION),
            zygotePreloadNameSuffixes = setOf(MAGICA_PRELOAD),
            labelPrefixes = setOf("KernelSU"),
            launcherClassSuffixes = setOf(UI_MAIN_ACTIVITY),
            signingCertificates = setOf(kernelSuOfficialCert, kernelSuKowx712Cert),
            nativePayloads = setOf(KSUD),
        ),
        RootManagerSignature(
            family = RootManagerFamily.KERNEL_SU_NEXT,
            packageNames = setOf("com.rifsxd.ksunext"),
            codeNamespaces = setOf("com.rifsxd.ksunext"),
            applicationClassSuffixes = setOf(KERNEL_SU_APPLICATION),
            labelPrefixes = setOf("KernelSU-Next"),
            launcherClassSuffixes = setOf(UI_MAIN_ACTIVITY),
            signingCertificates = setOf(kernelSuNextCert),
            nativePayloads = setOf(KSUD),
        ),
        RootManagerSignature(
            family = RootManagerFamily.SUKI_SU,
            packageNames = setOf("com.sukisu.ultra"),
            codeNamespaces = setOf("com.sukisu.ultra"),
            applicationClassSuffixes = setOf(KERNEL_SU_APPLICATION),
            zygotePreloadNameSuffixes = setOf(MAGICA_PRELOAD),
            labelPrefixes = setOf("SukiSU"),
            launcherClassSuffixes = setOf(UI_MAIN_ACTIVITY),
            signingCertificates = setOf(sukiSuCert),
            nativePayloads = setOf(KSUD),
        ),
        RootManagerSignature(
            family = RootManagerFamily.RE_SUKI_SU,
            packageNames = setOf("com.resukisu.resukisu"),
            // BakaSU keeps the old applicationId but moved its code namespace to org.bakasu.bakasu.
            codeNamespaces = setOf("org.bakasu.bakasu", "com.resukisu.resukisu"),
            applicationClassSuffixes = setOf(KERNEL_SU_APPLICATION),
            zygotePreloadNameSuffixes = setOf(MAGICA_PRELOAD),
            labelPrefixes = setOf("ReSukiSU", "BakaSU"),
            launcherClassSuffixes = setOf(UI_MAIN_ACTIVITY),
            signingCertificates = setOf(bakaSuCert),
            nativePayloads = setOf(KSUD),
        ),
        RootManagerSignature(
            family = RootManagerFamily.APATCH,
            packageNames = setOf("me.bmax.apatch"),
            // me.bmax.apatch.APApplication matches strongly through the namespace; the bare simple name only corroborates.
            codeNamespaces = setOf("me.bmax.apatch"),
            genericApplicationClassSuffixes = setOf(".APApplication"),
            zygotePreloadNameSuffixes = setOf(MAGICA_PRELOAD),
            labelPrefixes = setOf("APatch"),
            launcherClassSuffixes = setOf(UI_MAIN_ACTIVITY),
            // KernelPatch authorises the manager by its superkey, so no manager certificate is published.
            nativePayloads = setOf("libapd.so", "libkptools.so", "libkpatch.so"),
        ),
        RootManagerSignature(
            family = RootManagerFamily.SK_ROOT,
            packageNames = setOf("com.linux.permissionmanager"),
            // The Pro build's com.linux.permissionmanager.helper.AppZygotePreload matches through the namespace;
            // its `.helper.AppZygotePreload` suffix alone is too generic to stand as a strong anchor.
            codeNamespaces = setOf("com.linux.permissionmanager"),
            // Both builds label themselves "SKRoot(Lite)" / "SKRoot(Pro)"; "PermissionManager" is only the project name.
            labelPrefixes = setOf("SKRoot"),
            launcherClassSuffixes = setOf(".MainActivity"),
        ),
        RootManagerSignature(
            family = RootManagerFamily.MAGISK,
            packageNames = setOf("com.topjohnwu.magisk", "io.github.vvb2060.magisk"),
            // The `.core.App` suffix alone is too generic; under the com.topjohnwu.magisk namespace it is not.
            // A repackaged (hidden) Magisk randomises these names and re-signs with a fresh key.
            codeNamespaces = setOf("com.topjohnwu.magisk"),
            labelPrefixes = setOf("Magisk"),
            launcherClassSuffixes = setOf(UI_MAIN_ACTIVITY),
            nativePayloads = setOf("libmagisk.so", "libmagiskinit.so"),
        ),
    )
}
