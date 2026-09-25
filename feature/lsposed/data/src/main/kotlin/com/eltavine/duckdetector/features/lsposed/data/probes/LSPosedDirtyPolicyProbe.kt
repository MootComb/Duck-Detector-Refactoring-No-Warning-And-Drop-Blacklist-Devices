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

package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.capability.selinuxpolicy.data.DedicatedCarrierState
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValiditySnapshot
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodOutcome
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity

data class LSPosedDirtyPolicyProbeResult(
    /** At least one oracle passed its own checks, so its allowed edges describe the live policy. */
    val available: Boolean,
    /** At least one oracle ran in the expected carrier, whether or not it passed its checks. */
    val oracleReportable: Boolean = available,
    val probeAttempted: Boolean,
    val carrierContext: String?,
    val carrierMatchesExpected: Boolean,
    val controlsPassed: Boolean,
    val stable: Boolean,
    val queryMethod: String,
    val accessControlAllowed: Boolean?,
    val negativeControlRejected: Boolean?,
    val systemServerExecmemAllowed: Boolean?,
    val magiskBinderCallAllowed: Boolean?,
    val ksuFileReadAllowed: Boolean?,
    val lsposedFileReadAllowed: Boolean?,
    /** The LSPosed rule verdict came from an oracle that passed its own checks. */
    val lsposedFileReadTrusted: Boolean = false,
    val failureReason: String?,
    val notes: List<String>,
    val signals: List<LSPosedSignal>,
) {
    val hitCount: Int
        get() = signals.size

    val carrierState: DedicatedCarrierState
        get() = when {
            carrierContext != null && carrierMatchesExpected -> DedicatedCarrierState.OK
            carrierContext != null && !carrierMatchesExpected -> DedicatedCarrierState.UNTRUSTED
            else -> DedicatedCarrierState.FAILED
        }

    val summary: String
        get() = when {
            lsposedFileReadAllowed == true && lsposedFileReadTrusted && carrierState == DedicatedCarrierState.OK ->
                "LSPosed rule present"

            lsposedFileReadAllowed == true && carrierState == DedicatedCarrierState.OK -> "LSPosed rule (untrusted oracle)"
            hitCount > 0 -> "$hitCount dirty rule(s)"
            carrierState == DedicatedCarrierState.UNTRUSTED -> "Untrusted carrier"
            !available && oracleReportable -> "Untrusted oracle"
            !available && carrierState == DedicatedCarrierState.OK -> "Oracle unavailable"
            !available -> "Carrier failed"
            else -> "Clean"
        }

    val outcome: LSPosedMethodOutcome
        get() = when {
            signals.any { it.severity == LSPosedSignalSeverity.DANGER } -> LSPosedMethodOutcome.DETECTED
            signals.any { it.severity == LSPosedSignalSeverity.WARNING } -> LSPosedMethodOutcome.WARNING
            !available -> LSPosedMethodOutcome.SUPPORT
            else -> LSPosedMethodOutcome.CLEAN
        }

    val detail: String
        get() = buildString {
            append("Runs DirtySepolicy-style access queries through the existing app_zygote SELinux carrier. ")
            append("The LSPosed-specific rule is untrusted_app -> lsposed_file:file read.")
            appendLine()
            append("Carrier=").append(carrierContext ?: "<unreadable>")
            append(" | carrier state=").append(carrierState.label)
            append(" | carrier match=").append(if (carrierMatchesExpected) "yes" else "no")
            append(" | controls=").append(if (controlsPassed) "passed" else "failed")
            append(" | repeatability=").append(if (stable) "stable" else "unstable")
            append(" | query=").append(queryMethod)
            appendLine()
            append("access control=").append(ruleLabel(accessControlAllowed))
            append(" | negative control rejected=").append(yesNoLabel(negativeControlRejected))
            append(" | system_server execmem=").append(ruleLabel(systemServerExecmemAllowed))
            append(" | Magisk binder=").append(ruleLabel(magiskBinderCallAllowed))
            append(" | KernelSU file read=").append(ruleLabel(ksuFileReadAllowed))
            append(" | LSPosed file read=").append(ruleLabel(lsposedFileReadAllowed))
            failureReason?.takeIf { it.isNotBlank() }?.let {
                appendLine()
                append(it)
            }
            notes.take(4).forEach { note ->
                appendLine()
                append(note)
            }
        }

    private fun ruleLabel(value: Boolean?): String {
        return when (value) {
            true -> "allowed"
            false -> "denied"
            null -> "unknown"
        }
    }

    private fun yesNoLabel(value: Boolean?): String {
        return when (value) {
            true -> "yes"
            false -> "no"
            null -> "unknown"
        }
    }
}

class LSPosedDirtyPolicyProbe {
    fun run(snapshot: SelinuxContextValiditySnapshot): LSPosedDirtyPolicyProbeResult {
        val nativeTrack = dirtyPolicyTrack(snapshot, source = "native")
        val javaTrack = dirtyPolicyTrack(snapshot, source = "java")
        val tracks = listOf(nativeTrack, javaTrack)
        val reportable = tracks.any { it.reportable }
        val trusted = tracks.any { it.trusted }
        val aggregatedSignals = buildAggregatedSignals(nativeTrack, javaTrack)
        val systemServerExecmemAllowed = ruleVerdict(nativeTrack, nativeTrack.systemServerExecmemAllowed, javaTrack, javaTrack.systemServerExecmemAllowed)?.allowed
        val magiskBinderCallAllowed = ruleVerdict(nativeTrack, nativeTrack.magiskBinderCallAllowed, javaTrack, javaTrack.magiskBinderCallAllowed)?.allowed
        val ksuFileReadAllowed = ruleVerdict(nativeTrack, nativeTrack.ksuFileReadAllowed, javaTrack, javaTrack.ksuFileReadAllowed)?.allowed
        val lsposedFileRead = ruleVerdict(nativeTrack, nativeTrack.lsposedFileReadAllowed, javaTrack, javaTrack.lsposedFileReadAllowed)
        val carrierContext = nativeTrack.carrierContext ?: javaTrack.carrierContext
        val carrierMatchesExpected = nativeTrack.carrierMatchesExpected || javaTrack.carrierMatchesExpected
        val controlsPassed = tracks.any { it.reportable && it.controlsPassed }
        val stable = tracks.any { it.reportable && it.stable }
        val failureReason = listOfNotNull(nativeTrack.failureReason, javaTrack.failureReason)
            .distinct()
            .joinToString(" ; ")
            .ifBlank { null }
        val notes = buildList {
            add("Native dedicated=${nativeTrack.summary()}")
            add("Java dedicated=${javaTrack.summary()}")
        }

        return LSPosedDirtyPolicyProbeResult(
            available = trusted,
            oracleReportable = reportable,
            probeAttempted = tracks.any { it.probeAttempted },
            carrierContext = carrierContext,
            carrierMatchesExpected = carrierMatchesExpected,
            controlsPassed = controlsPassed,
            stable = stable,
            queryMethod = listOf(nativeTrack.queryMethod, javaTrack.queryMethod)
                .filter { it.isNotBlank() }
                .distinct()
                .joinToString(" + ")
                .ifBlank { "android.os.SELinux.checkSELinuxAccess" },
            accessControlAllowed = mergeReportedBoolean(nativeTrack, nativeTrack.accessControlAllowed, javaTrack, javaTrack.accessControlAllowed),
            negativeControlRejected = mergeReportedBoolean(nativeTrack, nativeTrack.negativeControlRejected, javaTrack, javaTrack.negativeControlRejected),
            systemServerExecmemAllowed = systemServerExecmemAllowed,
            magiskBinderCallAllowed = magiskBinderCallAllowed,
            ksuFileReadAllowed = ksuFileReadAllowed,
            lsposedFileReadAllowed = lsposedFileRead?.allowed,
            lsposedFileReadTrusted = lsposedFileRead?.trusted == true,
            failureReason = failureReason,
            notes = notes,
            signals = aggregatedSignals.distinctBy { it.id },
        )
    }

    private fun buildAggregatedSignals(
        nativeTrack: DirtyPolicyTrack,
        javaTrack: DirtyPolicyTrack,
    ): List<LSPosedSignal> {
        val sources = listOf(nativeTrack.source, javaTrack.source)
            .distinct()
            .joinToString(" + ")
        return listOfNotNull(
            policySignal(
                verdict = ruleVerdict(nativeTrack, nativeTrack.systemServerExecmemAllowed, javaTrack, javaTrack.systemServerExecmemAllowed),
                id = "policy_system_server_execmem",
                label = "system_server execmem",
                severity = LSPosedSignalSeverity.WARNING,
                detail = "The $sources app_zygote SELinux access oracle reported system_server -> system_server:process execmem as allowed.",
            ),
            policySignal(
                verdict = ruleVerdict(nativeTrack, nativeTrack.magiskBinderCallAllowed, javaTrack, javaTrack.magiskBinderCallAllowed),
                id = "policy_magisk_binder_call",
                label = "Magisk binder",
                severity = LSPosedSignalSeverity.WARNING,
                detail = "The $sources app_zygote SELinux access oracle reported untrusted_app -> magisk:binder call as allowed. This is supporting dirty-policy evidence, not an LSPosed-specific rule.",
            ),
            policySignal(
                verdict = ruleVerdict(nativeTrack, nativeTrack.ksuFileReadAllowed, javaTrack, javaTrack.ksuFileReadAllowed),
                id = "policy_ksu_file_read",
                label = "KernelSU file read",
                severity = LSPosedSignalSeverity.WARNING,
                detail = "The $sources app_zygote SELinux access oracle reported untrusted_app -> ksu_file:file read as allowed. This is supporting dirty-policy evidence, not an LSPosed-specific rule.",
            ),
            policySignal(
                verdict = ruleVerdict(nativeTrack, nativeTrack.lsposedFileReadAllowed, javaTrack, javaTrack.lsposedFileReadAllowed),
                id = "policy_lsposed_file_read",
                label = "LSPosed file read",
                severity = LSPosedSignalSeverity.DANGER,
                detail = "The $sources app_zygote SELinux access oracle reported untrusted_app -> lsposed_file:file read as allowed.",
            ),
        )
    }

    private data class RuleVerdict(val allowed: Boolean, val trusted: Boolean)

    // An oracle that passed its own controls decides. An answer from one that failed them is kept,
    // but only at lower confidence: its allowed edges may describe a broken query path.
    private fun ruleVerdict(
        nativeTrack: DirtyPolicyTrack,
        nativeValue: Boolean?,
        javaTrack: DirtyPolicyTrack,
        javaValue: Boolean?,
    ): RuleVerdict? {
        aggregateVerdict(nativeValue.takeIf { nativeTrack.trusted }, javaValue.takeIf { javaTrack.trusted })
            ?.let { return RuleVerdict(allowed = it, trusted = true) }
        return aggregateReportedVerdict(nativeTrack, nativeValue, javaTrack, javaValue)
            ?.let { RuleVerdict(allowed = it, trusted = false) }
    }

    private fun aggregateReportedVerdict(
        nativeTrack: DirtyPolicyTrack,
        nativeValue: Boolean?,
        javaTrack: DirtyPolicyTrack,
        javaValue: Boolean?,
    ): Boolean? {
        return aggregateVerdict(
            nativeValue.takeIf { nativeTrack.reportable },
            javaValue.takeIf { javaTrack.reportable },
        )
    }

    private fun aggregateVerdict(nativeValue: Boolean?, javaValue: Boolean?): Boolean? {
        return when {
            nativeValue != null && javaValue != null && nativeValue != javaValue -> null
            nativeValue == true || javaValue == true -> true
            nativeValue == false || javaValue == false -> false
            else -> null
        }
    }

    private fun mergeBoolean(nativeValue: Boolean?, javaValue: Boolean?): Boolean? {
        return when {
            nativeValue != null && javaValue != null && nativeValue != javaValue -> null
            nativeValue != null -> nativeValue
            else -> javaValue
        }
    }

    private fun mergeReportedBoolean(
        nativeTrack: DirtyPolicyTrack,
        nativeValue: Boolean?,
        javaTrack: DirtyPolicyTrack,
        javaValue: Boolean?,
    ): Boolean? {
        return mergeBoolean(
            nativeValue.takeIf { nativeTrack.reportable },
            javaValue.takeIf { javaTrack.reportable },
        )
    }

    private fun dirtyPolicyTrack(
        snapshot: SelinuxContextValiditySnapshot,
        source: String,
    ): DirtyPolicyTrack {
        return if (source == "native") {
            DirtyPolicyTrack(
                source = source,
                trusted = snapshot.dirtyPolicyTrusted,
                available = snapshot.dirtyPolicyAvailable,
                probeAttempted = snapshot.dirtyPolicyProbeAttempted,
                carrierContext = snapshot.dirtyPolicyCarrierContext,
                carrierMatchesExpected = snapshot.dirtyPolicyCarrierMatchesExpected,
                controlsPassed = snapshot.dirtyPolicyControlsPassed,
                stable = snapshot.dirtyPolicyStable,
                queryMethod = snapshot.dirtyPolicyQueryMethod.ifBlank { "android.os.SELinux.checkSELinuxAccess" },
                accessControlAllowed = snapshot.dirtyPolicyAccessControlAllowed,
                negativeControlRejected = snapshot.dirtyPolicyNegativeControlRejected,
                systemServerExecmemAllowed = snapshot.dirtyPolicySystemServerExecmemAllowed,
                magiskBinderCallAllowed = snapshot.dirtyPolicyMagiskBinderCallAllowed,
                ksuFileReadAllowed = snapshot.dirtyPolicyKsuFileReadAllowed,
                lsposedFileReadAllowed = snapshot.dirtyPolicyLsposedFileReadAllowed,
                failureReason = snapshot.dirtyPolicyFailureReason,
            )
        } else {
            DirtyPolicyTrack(
                source = source,
                trusted = snapshot.javaDirtyPolicyTrusted,
                available = snapshot.javaDirtyPolicyAvailable,
                probeAttempted = snapshot.javaDirtyPolicyProbeAttempted,
                carrierContext = snapshot.javaDirtyPolicyCarrierContext,
                carrierMatchesExpected = snapshot.javaDirtyPolicyCarrierMatchesExpected,
                controlsPassed = snapshot.javaDirtyPolicyControlsPassed,
                stable = snapshot.javaDirtyPolicyStable,
                queryMethod = snapshot.javaDirtyPolicyQueryMethod.ifBlank { "android.os.SELinux.checkSELinuxAccess" },
                accessControlAllowed = snapshot.javaDirtyPolicyAccessControlAllowed,
                negativeControlRejected = snapshot.javaDirtyPolicyNegativeControlRejected,
                systemServerExecmemAllowed = snapshot.javaDirtyPolicySystemServerExecmemAllowed,
                magiskBinderCallAllowed = snapshot.javaDirtyPolicyMagiskBinderCallAllowed,
                ksuFileReadAllowed = snapshot.javaDirtyPolicyKsuFileReadAllowed,
                lsposedFileReadAllowed = snapshot.javaDirtyPolicyLsposedFileReadAllowed,
                failureReason = snapshot.javaDirtyPolicyFailureReason,
            )
        }
    }

    private data class DirtyPolicyTrack(
        val source: String,
        val trusted: Boolean,
        val available: Boolean,
        val probeAttempted: Boolean,
        val carrierContext: String?,
        val carrierMatchesExpected: Boolean,
        val controlsPassed: Boolean,
        val stable: Boolean,
        val queryMethod: String,
        val accessControlAllowed: Boolean?,
        val negativeControlRejected: Boolean?,
        val systemServerExecmemAllowed: Boolean?,
        val magiskBinderCallAllowed: Boolean?,
        val ksuFileReadAllowed: Boolean?,
        val lsposedFileReadAllowed: Boolean?,
        val failureReason: String?,
    ) {
        val reportable: Boolean
            get() = available && probeAttempted && carrierMatchesExpected

        fun summary(): String {
            return buildString {
                append(
                    when {
                        trusted -> "trusted"
                        reportable -> "untrusted"
                        else -> "unavailable"
                    },
                )
                append(" carrier=")
                append(carrierContext ?: "<unreadable>")
                append(" controls=")
                append(if (controlsPassed) "passed" else "failed")
                append(" stable=")
                append(if (stable) "yes" else "no")
                failureReason?.takeIf { it.isNotBlank() }?.let {
                    append(" reason=")
                    append(it)
                }
            }
        }
    }

    private fun policySignal(
        verdict: RuleVerdict?,
        id: String,
        label: String,
        severity: LSPosedSignalSeverity,
        detail: String,
    ): LSPosedSignal? {
        if (verdict?.allowed != true) {
            return null
        }
        return LSPosedSignal(
            id = id,
            label = label,
            value = "Allowed",
            group = LSPosedSignalGroup.POLICY,
            severity = if (verdict.trusted) severity else LSPosedSignalSeverity.WARNING,
            detail = if (verdict.trusted) {
                detail
            } else {
                "$detail The oracle failed its own controls, so this is lower-confidence evidence."
            },
        )
    }
}
