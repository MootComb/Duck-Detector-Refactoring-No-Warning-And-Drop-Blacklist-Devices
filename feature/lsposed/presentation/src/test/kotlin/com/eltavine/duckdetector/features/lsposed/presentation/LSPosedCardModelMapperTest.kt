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

package com.eltavine.duckdetector.features.lsposed.presentation

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethod
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodOutcome
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodResult
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedPackageVisibility
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedProbe
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedStage
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedRowIcon
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LSPosedCardModelMapperTest {

    private val mapper = LSPosedCardModelMapper()

    @Test
    fun `zygote permission unavailable keeps clean signal report at support`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            zygotePermissionAvailable = false,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertTrue(model.verdict.contains("reduced coverage", ignoreCase = true))
    }

    @Test
    fun `native heap unavailable keeps clean signal report at support`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            nativeHeapAvailable = false,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertEquals("N/A", model.scanRows.single { it.label == "Native heap" }.value)
    }

    @Test
    fun `unreadable proc maps keeps a clean signal report at support`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            nativeMapsAvailable = false,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertEquals("N/A", model.scanRows.single { it.label == "Native maps" }.value)
    }

    @Test
    fun `dirty policy signal surfaces in policy section and methods`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            signals = listOf(
                LSPosedSignal(
                    id = "policy_lsposed_file_read",
                    probe = LSPosedProbe.DIRTY_POLICY,
                    label = "LSPosed file read",
                    value = "Allowed",
                    group = LSPosedSignalGroup.POLICY,
                    severity = LSPosedSignalSeverity.DANGER,
                    detail = "untrusted_app -> lsposed_file:file read was allowed.",
                ),
            ),
            methods = listOf(
                LSPosedMethodResult(
                    method = LSPosedMethod.DIRTY_SEPOLICY,
                    summary = "LSPosed rule present",
                    outcome = LSPosedMethodOutcome.DETECTED,
                    detail = "Dirty policy details.",
                ),
            ),
            dirtyPolicyAvailable = true,
            lsposedPolicyRuleExposed = true,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.DANGER, model.status.severity)
        assertTrue(model.verdict.contains("Dirty SELinux policy exposes LSPosed rule"))
        assertTrue(
            model.policyRows.any {
                it.label == "LSPosed file read" && it.value == "Allowed"
            },
        )
        assertTrue(
            model.methodRows.any {
                it.label == "Dirty sepolicy" && it.value == "LSPosed rule present"
            },
        )
    }

    @Test
    fun `dirty policy unavailable does not downgrade otherwise clean LSPosed report`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            dirtyPolicyAvailable = false,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertEquals("LSPosed scan has reduced coverage", model.verdict)
        assertTrue(
            model.policyRows.any {
                it.label == "SELinux policy" && it.value == "Unavailable"
            },
        )
    }

    @Test
    fun `supporting policy warning does not mask stronger runtime verdict`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            dirtyPolicyAvailable = true,
            signals = listOf(
                LSPosedSignal(
                    id = "runtime_bridge_field",
                    probe = LSPosedProbe.BRIDGE_FIELD,
                    label = "XposedBridge fields",
                    value = "Detected",
                    group = LSPosedSignalGroup.RUNTIME,
                    severity = LSPosedSignalSeverity.DANGER,
                    detail = "Bridge field exposed.",
                ),
                LSPosedSignal(
                    id = "policy_magisk_binder_call",
                    probe = LSPosedProbe.DIRTY_POLICY,
                    label = "Magisk binder",
                    value = "Allowed",
                    group = LSPosedSignalGroup.POLICY,
                    severity = LSPosedSignalSeverity.WARNING,
                    detail = "Supporting dirty-policy evidence.",
                ),
            ),
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.DANGER, model.status.severity)
        assertEquals("1 high-risk LSPosed signal(s)", model.verdict)
    }

    @Test
    fun `signal rows take their icon from their probe`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            signals = listOf(
                signal("binder_serial_bridge", LSPosedProbe.BINDER, LSPosedSignalGroup.BINDER),
                signal("policy_ksu_file_read", LSPosedProbe.DIRTY_POLICY, LSPosedSignalGroup.POLICY),
                signal("pkg_org_lsposed_manager", LSPosedProbe.PACKAGE, LSPosedSignalGroup.PACKAGES),
                signal("logcat_tag_lspd", LSPosedProbe.LOGCAT, LSPosedSignalGroup.RUNTIME),
            ),
        )

        val model = mapper.map(report)

        assertEquals(listOf(LSPosedRowIcon.BRIDGE), model.binderRows.map { it.icon })
        assertEquals(listOf(LSPosedRowIcon.POLICY), model.policyRows.map { it.icon })
        assertEquals(listOf(LSPosedRowIcon.PACKAGE), model.packageRows.map { it.icon })
        assertEquals(listOf<LSPosedRowIcon?>(null), model.runtimeRows.map { it.icon })
    }

    @Test
    fun `loading method and scan rows keep their labels and icons`() {
        val model = mapper.map(LSPosedReport.loading())

        assertEquals(LSPosedMethod.entries.map { it.label }, model.methodRows.map { it.label })
        assertEquals(
            listOf(LSPosedMethod.XPOSED_BRIDGE_FIELDS, LSPosedMethod.BINDER_BRIDGE).map { it.label },
            model.methodRows.filter { it.icon == LSPosedRowIcon.BRIDGE }.map { it.label },
        )
        assertEquals(
            mapOf(
                "Bridge field hits" to LSPosedRowIcon.BRIDGE,
                "Stack hits" to LSPosedRowIcon.HOOK,
                "Dirty policy hits" to LSPosedRowIcon.POLICY,
                "Dirty policy availability" to LSPosedRowIcon.POLICY,
                "Manager packages" to LSPosedRowIcon.PACKAGE,
                "Native heap" to LSPosedRowIcon.MEMORY,
                "Package visibility" to LSPosedRowIcon.PACKAGE,
            ),
            model.scanRows.filter { it.icon != null }.associate { it.label to it.icon },
        )
        assertEquals(19, model.scanRows.size)
    }

    private fun signal(id: String, probe: LSPosedProbe, group: LSPosedSignalGroup) = LSPosedSignal(
        id = id,
        probe = probe,
        label = id,
        value = "Detected",
        group = group,
        severity = LSPosedSignalSeverity.WARNING,
        detail = "detail",
    )
}
