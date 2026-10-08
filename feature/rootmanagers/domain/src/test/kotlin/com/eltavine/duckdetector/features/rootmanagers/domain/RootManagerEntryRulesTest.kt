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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RootManagerEntryRulesTest {

    @Test
    fun `an official KernelSU install matches every field as a high-confidence entry`() {
        val entries = RootManagerEntryRules.entries(
            listOf(
                launcherApp(
                    packageName = "me.weishu.kernelsu",
                    applicationClassName = "me.weishu.kernelsu.KernelSUApplication",
                    componentClassName = "me.weishu.kernelsu.ui.MainActivity",
                    label = "KernelSU",
                    zygotePreloadName = "me.weishu.kernelsu.magica.AppZygotePreload",
                    nativePayloads = setOf("libksud.so"),
                ),
                packageManagerApp("me.weishu.kernelsu", signingCertificates = listOf(certOf(RootManagerFamily.KERNEL_SU))),
            ),
        )

        val entry = entries.single()
        assertEquals(RootManagerFamily.KERNEL_SU, entry.family)
        assertEquals(RootManagerConfidence.HIGH, entry.confidence)
        assertEquals(enumValues<RootManagerAnchor>().toSet() - RootManagerAnchor.APPLICATION_CLASS_NAME, entry.anchors)
        assertEquals(certOf(RootManagerFamily.KERNEL_SU), entry.matchedCertificate)
    }

    @Test
    fun `a manager renamed past every name is still caught by its kernel's manager key`() {
        val entry = RootManagerEntryRules.match(
            packageManagerApp("yhaxhr.birgvn.bmwbne", signingCertificates = listOf(certOf(RootManagerFamily.SUKI_SU))),
        )

        assertEquals(RootManagerFamily.SUKI_SU, entry?.family)
        assertEquals(RootManagerConfidence.HIGH, entry?.confidence)
        assertEquals(setOf(RootManagerAnchor.SIGNING_CERTIFICATE), entry?.anchors)
    }

    @Test
    fun `the manager key separates forks that share the KernelSU class names`() {
        val entry = RootManagerEntryRules.match(
            packageManagerApp(
                packageName = "com.example.custom",
                applicationClassName = "com.example.custom.KernelSUApplication",
                zygotePreloadName = "com.example.custom.magica.AppZygotePreload",
                signingCertificates = listOf(certOf(RootManagerFamily.RE_SUKI_SU)),
                nativePayloads = setOf("libksud.so"),
            ),
        )

        assertEquals(RootManagerFamily.RE_SUKI_SU, entry?.family)
    }

    @Test
    fun `a spoofed KernelSU-Next in another profile lands on its own family through the label`() {
        val entry = RootManagerEntryRules.match(
            launcherApp(
                packageName = "yhaxhr.birgvn.bmwbne",
                profileUserId = 10,
                applicationClassName = "yhaxhr.birgvn.bmwbne.KernelSUApplication",
                componentClassName = "yhaxhr.birgvn.bmwbne.ui.MainActivity",
                label = "KernelSU-Next",
            ),
        )

        assertEquals(RootManagerFamily.KERNEL_SU_NEXT, entry?.family)
        assertEquals(RootManagerConfidence.HIGH, entry?.confidence)
    }

    @Test
    fun `a renamed package keeps its fork through the code namespace`() {
        val entry = RootManagerEntryRules.match(
            launcherApp(
                packageName = "com.example.renamed",
                applicationClassName = "com.sukisu.ultra.KernelSUApplication",
                componentClassName = "com.sukisu.ultra.ui.MainActivity",
                zygotePreloadName = "com.sukisu.ultra.magica.AppZygotePreload",
            ),
        )

        assertEquals(RootManagerFamily.SUKI_SU, entry?.family)
    }

    @Test
    fun `BakaSU keeps the ReSukiSU package but its own namespace`() {
        val entry = RootManagerEntryRules.match(
            launcherApp(
                packageName = "com.resukisu.resukisu",
                applicationClassName = "org.bakasu.bakasu.KernelSUApplication",
                zygotePreloadName = "org.bakasu.bakasu.magica.AppZygotePreload",
                label = "BakaSU",
            ),
        )

        assertEquals(RootManagerFamily.RE_SUKI_SU, entry?.family)
        assertEquals(RootManagerConfidence.HIGH, entry?.confidence)
    }

    @Test
    fun `a native payload alone identifies the lineage at medium confidence`() {
        val entry = RootManagerEntryRules.match(packageManagerApp("com.example.app", nativePayloads = setOf("libapd.so")))

        assertEquals(RootManagerFamily.APATCH, entry?.family)
        assertEquals(RootManagerConfidence.MEDIUM, entry?.confidence)
        assertEquals(setOf("libapd.so"), entry?.matchedPayloads)
    }

    @Test
    fun `a bare APApplication simple name only corroborates`() {
        val alone = RootManagerEntryRules.match(launcherApp("com.example.app", applicationClassName = "com.example.app.APApplication"))
        val withLabel = RootManagerEntryRules.match(
            launcherApp("com.example.app", applicationClassName = "com.example.app.APApplication", label = "APatch"),
        )

        assertNull(alone)
        assertEquals(RootManagerConfidence.LOW, withLabel?.confidence)
    }

    @Test
    fun `the SKRoot zygote preload matches through its namespace, not a generic suffix`() {
        val skRoot = RootManagerEntryRules.match(
            launcherApp("com.example.app", zygotePreloadName = "com.linux.permissionmanager.helper.AppZygotePreload"),
        )
        val unrelated = RootManagerEntryRules.match(
            launcherApp("com.example.app", zygotePreloadName = "com.example.app.helper.AppZygotePreload"),
        )

        assertEquals(RootManagerFamily.SK_ROOT, skRoot?.family)
        assertNull(unrelated)
    }

    @Test
    fun `a namespace never matches a longer sibling segment`() {
        assertNull(RootManagerEntryRules.match(launcherApp("me.weishu.kernelsufoo")))
    }

    @Test
    fun `a single weak field does not produce an entry`() {
        assertNull(RootManagerEntryRules.match(launcherApp("com.example.app", label = "KernelSU")))
    }

    @Test
    fun `two weak fields produce a low-confidence entry`() {
        val entry = RootManagerEntryRules.match(
            launcherApp("com.example.app", componentClassName = "com.example.app.MainActivity", label = "SKRoot(Lite)"),
        )

        assertEquals(RootManagerFamily.SK_ROOT, entry?.family)
        assertEquals(RootManagerConfidence.LOW, entry?.confidence)
    }

    @Test
    fun `a launcher view and the PackageManager view of one app merge into one entry`() {
        val entries = RootManagerEntryRules.entries(
            listOf(
                launcherApp("com.example.renamed", label = "SukiSU", componentClassName = "x.ui.MainActivity", hidesLauncherIcon = false),
                packageManagerApp("com.example.renamed", signingCertificates = listOf(certOf(RootManagerFamily.SUKI_SU))),
            ),
        )

        val entry = entries.single()
        assertEquals(RootManagerFamily.SUKI_SU, entry.family)
        assertTrue(RootManagerAnchor.SIGNING_CERTIFICATE in entry.anchors)
        assertTrue(RootManagerAnchor.LABEL in entry.anchors)
    }

    @Test
    fun `a manager that hid its launcher icon is concealed`() {
        val entry = RootManagerEntryRules.entries(
            listOf(
                launcherApp("me.weishu.kernelsu", componentClassName = "android.app.AppDetailsActivity", hidesLauncherIcon = true),
                packageManagerApp("me.weishu.kernelsu", signingCertificates = listOf(certOf(RootManagerFamily.KERNEL_SU))),
            ),
        ).single()

        assertTrue(entry.hidesLauncherIcon)
        assertTrue(entry.concealed)
        assertTrue(RootManagerAnchor.LAUNCHER_CLASS !in entry.anchors)
    }

    @Test
    fun `the same app in two profiles yields two entries`() {
        val entries = RootManagerEntryRules.entries(
            listOf(launcherApp("me.weishu.kernelsu", profileUserId = 0), launcherApp("me.weishu.kernelsu", profileUserId = 10)),
        )

        assertEquals(listOf(0, 10), entries.map { it.profileUserId })
    }

    @Test
    fun `an unrelated certificate and an empty enumeration produce no entries`() {
        val stranger = CertificateFingerprint(800, "0".repeat(64))

        assertNull(RootManagerEntryRules.match(packageManagerApp("com.example.app", signingCertificates = listOf(stranger))))
        assertEquals(emptyList<RootManagerEntry>(), RootManagerEntryRules.entries(emptyList()))
    }
}
