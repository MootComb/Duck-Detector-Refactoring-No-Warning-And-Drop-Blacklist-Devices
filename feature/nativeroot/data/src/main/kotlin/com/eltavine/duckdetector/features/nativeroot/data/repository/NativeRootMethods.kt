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

package com.eltavine.duckdetector.features.nativeroot.data.repository

import com.eltavine.duckdetector.features.nativeroot.data.native.NativeRootNativeSnapshot
import com.eltavine.duckdetector.features.nativeroot.data.native.SusfsProbeOutcome
import com.eltavine.duckdetector.features.nativeroot.data.probes.CgroupProcessLeakProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuManagerFingerprintProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuThroneHuntProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.MountNamespaceDriftProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.TempRootArtifactProbeResult
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethod
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodOutcome
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult

internal fun buildMethods(
    snapshot: NativeRootNativeSnapshot,
    findings: List<NativeRootFinding>,
    shellTmpDetail: String,
    rootProcessDetail: String,
    cgroupResult: CgroupProcessLeakProbeResult,
    mountNamespaceResult: MountNamespaceDriftProbeResult,
    managerFingerprintResult: KernelSuManagerFingerprintProbeResult,
    tempRootArtifactResult: TempRootArtifactProbeResult,
    throneHuntResult: KernelSuThroneHuntProbeResult,
): List<NativeRootMethodResult> {
    val directFindings =
        findings.filter { it.group == NativeRootGroup.SYSCALL || it.group == NativeRootGroup.SIDE_CHANNEL }
    val runtimeFindings =
        findings.filter {
            it.group == NativeRootGroup.PATH ||
                    it.group == NativeRootGroup.PROCESS ||
                    it.group == NativeRootGroup.PACKAGE
        }
    val kernelFindings = findings.filter { it.group == NativeRootGroup.KERNEL }
    val propertyFindings = findings.filter { it.group == NativeRootGroup.PROPERTY }

    return listOf(
        NativeRootMethodResult(
            method = NativeRootMethod.KSU_READONLY_SUPERCALL,
            summary = when {
                snapshot.ksuSupercallProbeHit && snapshot.kernelSuVersion > 0L -> "v${snapshot.kernelSuVersion}"
                snapshot.ksuSupercallProbeHit -> "Detected"
                snapshot.ksuSupercallBlocked -> "Blocked"
                snapshot.ksuSupercallAttempted -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                snapshot.ksuSupercallProbeHit -> NativeRootMethodOutcome.DETECTED
                snapshot.ksuSupercallBlocked -> NativeRootMethodOutcome.SUPPORT
                snapshot.ksuSupercallAttempted -> NativeRootMethodOutcome.CLEAN
                else -> NativeRootMethodOutcome.SUPPORT
            },
            detail = buildString {
                append("Uses a sacrificial child process to request a temporary [ksu_driver] fd through the KernelSU reboot-magic install path, then calls GET_INFO and CHECK_SAFEMODE without manager/root privileges.")
                if (snapshot.ksuSupercallBlocked) {
                    append("\nThe device seccomp policy trapped reboot() for the helper process before a [ksu_driver] fd could be installed.")
                } else if (snapshot.ksuSupercallProbeHit) {
                    append("\nFlags:")
                    append(if (snapshot.ksuSupercallLkm) " LKM" else " non-LKM")
                    append(if (snapshot.ksuSupercallLateLoad) ", late-load" else ", early-load")
                    if (snapshot.ksuSupercallPrBuild) {
                        append(", PR build")
                    }
                    if (snapshot.ksuSupercallManager) {
                        append(", manager context")
                    }
                    append("\nSafe mode: ")
                    append(if (snapshot.ksuSupercallSafeMode) "enabled" else "disabled")
                } else if (!snapshot.ksuSupercallAttempted) {
                    append("\nThe helper process did not return a valid result, so this direct probe stayed unavailable.")
                }
            },
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.NR_SUPERCALL_PROBE,
            summary = when {
                snapshot.kernelPatchSideChannel -> "Detected"
                snapshot.kernelPatchSideChannelAvailable -> "No pre-fix delay"
                else -> "Unavailable"
            },
            outcome = when {
                snapshot.kernelPatchSideChannel -> NativeRootMethodOutcome.DETECTED
                snapshot.kernelPatchSideChannelAvailable -> NativeRootMethodOutcome.CLEAN
                else -> NativeRootMethodOutcome.SUPPORT
            },
            detail = buildString {
                append("Times __NR_supercall (syscall 45, the arm64 truncate slot KernelPatch takes over) with a 128-byte key and with an empty key. ")
                append("KernelPatch older than commit 84169d5d6be12e589ccac81d71dcebb80b22043a copied the key with strncpy_from_user before authorizing it, so the longer key cost measurably more.\n")
                append("That commit stopped copying before auth, which puts a fixed build back on the same footing as an unmodified kernel. ")
                append("So a result here that is not \"Detected\" rules out the older leak only, not KernelPatch itself; the superkey probe is what covers current builds.\n")
                append("Test Result: ${snapshot.kernelPatchSideChannelDetail}")
            },
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.KERNELPATCH_SUPERKEY,
            summary = when {
                snapshot.kernelPatchSuperkey -> "Detected"
                !snapshot.kernelPatchSuperkeyAvailable -> "Unavailable"
                else -> "Clean"
            },
            outcome = when {
                snapshot.kernelPatchSuperkey -> NativeRootMethodOutcome.DETECTED
                !snapshot.kernelPatchSuperkeyAvailable -> NativeRootMethodOutcome.SUPPORT
                else -> NativeRootMethodOutcome.CLEAN
            },
            detail = buildString {
                append("Passes __NR_supercall an untouched anonymous page together with a length the kernel rejects before it derives a user pointer, ")
                append("so a stock kernel never reads arg0 and the page keeps its empty PTE.\n")
                append("KernelPatch reads arg0 to compare it against the superkey ahead of the syscall body, which faults the page in; mincore then reports it resident.\n")
                append("This is a state check, so it does not depend on timing or CPU frequency.\n")
                append("A positive residency hit is conclusive on any kernel version, but a negative result is only treated as Clean inside the probe's conservative faulting-uaccess scope (kernel <= 6.6). Kernel 6.7+, or an unparseable kernel release, is reported as Unavailable instead of turning a known nofault blind spot into a false Clean verdict.\n")
                append("A run with a failed page mapping, no control page, a resident control page, a pre-resident attempt, an incomplete attempt set, or a failed residency read is also reported as Unavailable rather than Clean.\n")
                append("Test Result: ${snapshot.kernelPatchSuperkeyDetail}")
            },
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.DEVPTS_PERMISSION_CHECK,
            summary = when {
                snapshot.devptsAbnormalPermission -> "Detected"
                snapshot.devptsAbnormalPermissionCheckedCount == 0 -> "Unavailable"
                !snapshot.devptsAbnormalPermissionAvailable -> "Limited"
                else -> "Clean"
            },
            outcome = when {
                snapshot.devptsAbnormalPermission -> NativeRootMethodOutcome.DETECTED
                snapshot.devptsAbnormalPermissionCheckedCount == 0 -> NativeRootMethodOutcome.SUPPORT
                !snapshot.devptsAbnormalPermissionAvailable -> NativeRootMethodOutcome.SUPPORT
                else -> NativeRootMethodOutcome.CLEAN
            },
            detail = buildString {
                append("Checks /dev/pts owner uid and SELinux labels from existing PTYs plus a freshly created PTY.")
                append("\nIn a normal system, the probe should not find uid 0 PTYs or a u:object_r:ksu_file:s0 label.")
                if (!snapshot.devptsAbnormalPermission) {
                    when {
                        snapshot.devptsAbnormalPermissionCheckedCount == 0 ->
                            append("\nNo usable PTY sample was collected, so this probe stayed unavailable.")

                        !snapshot.devptsAbnormalPermissionAvailable ->
                            append("\nThe probe ran, but coverage was partial, so this result stays support-only.")
                    }
                }
                append("\nTest Result: \n")
                append(snapshot.devptsAbnormalPermissionDetail)
            },
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.PERMISSION_BOUNDARY_CHECK,
            summary = when {
                snapshot.permissionBoundaryDetected -> "Detected"
                !snapshot.permissionBoundaryAvailable -> "Unavailable"
                else -> "Clean"
            },
            outcome = when {
                snapshot.permissionBoundaryDetected -> NativeRootMethodOutcome.DETECTED
                !snapshot.permissionBoundaryAvailable -> NativeRootMethodOutcome.SUPPORT
                else -> NativeRootMethodOutcome.CLEAN
            },
            detail = buildString {
                append("Checks SELinux's netlink boundaries for RTM_GETLINK and RTM_GETNEIGH.")
                append("\nAOSP policy denies RTM_GETLINK to apps targeting SDK 30 or later on Android 11 and 12 and to every app from Android 13, and denies RTM_GETNEIGH from Android 13 to apps targeting SDK 32 or later; CTS checks both. Where a denial does not apply to this process, that check is not applicable.")
                append("\nAn answered request that exposes a physical MAC or a LAN neighbour shows SELinux did not enforce the denial, which modified policy, a permissive domain or a kernel without Android's netlink patches can cause.")
                append("\nTest Result:\n")
                append(snapshot.permissionBoundaryDetail)
            },
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.PRCTL_PROBE,
            summary = when {
                snapshot.prctlProbeHit && snapshot.kernelSuVersion > 0L -> "v${snapshot.kernelSuVersion}"
                snapshot.prctlProbeHit -> "Detected"
                snapshot.available -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                snapshot.prctlProbeHit -> NativeRootMethodOutcome.DETECTED
                snapshot.available -> NativeRootMethodOutcome.CLEAN
                else -> NativeRootMethodOutcome.SUPPORT
            },
            detail = "KernelSU magic prctl probe using option 0xDEADBEEF.",
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.SUSFS_SIDE_CHANNEL,
            summary = when (snapshot.susfsProbeOutcome) {
                SusfsProbeOutcome.KILLED -> "SIGKILL"
                SusfsProbeOutcome.CHANGED_UID -> "UID changed"
                SusfsProbeOutcome.DENIED -> "Normal"
                SusfsProbeOutcome.NOT_OBSERVED -> "Unavailable"
            },
            outcome = when (snapshot.susfsProbeOutcome) {
                SusfsProbeOutcome.KILLED, SusfsProbeOutcome.CHANGED_UID -> NativeRootMethodOutcome.DETECTED
                SusfsProbeOutcome.DENIED -> NativeRootMethodOutcome.CLEAN
                SusfsProbeOutcome.NOT_OBSERVED -> NativeRootMethodOutcome.SUPPORT
            },
            detail = buildString {
                append("Fork child and attempt setresuid to a lower UID. Old SUSFS/KSU hooks can kill the child instead of returning EPERM.")
                if (snapshot.susfsProbeDetail.isNotBlank()) {
                    append("\nTest Result: ")
                    append(snapshot.susfsProbeDetail)
                }
            },
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.SELF_PROCESS_IOC,
            summary = when {
                snapshot.selfSuDomain -> "su domain"
                snapshot.selfKsuDriverFdCount + snapshot.selfKsuFdwrapperFdCount > 0 -> "FD residue"
                snapshot.selfContext.isNotBlank() -> "Normal"
                snapshot.available -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                snapshot.selfSuDomain ||
                        snapshot.selfKsuDriverFdCount + snapshot.selfKsuFdwrapperFdCount > 0 ->
                    NativeRootMethodOutcome.DETECTED

                snapshot.available -> NativeRootMethodOutcome.CLEAN
                else -> NativeRootMethodOutcome.SUPPORT
            },
            detail = buildString {
                append("Checks whether the current app process already runs in the KernelSU su SELinux domain or holds ambient [ksu_driver]/[ksu_fdwrapper] descriptors before escalation.")
                if (snapshot.selfContext.isNotBlank()) {
                    append("\nContext: ")
                    append(snapshot.selfContext)
                }
                append("\nDriver FDs: ")
                append(snapshot.selfKsuDriverFdCount)
                append("\nFD wrapper FDs: ")
                append(snapshot.selfKsuFdwrapperFdCount)
            },
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.ISOLATED_MOUNT_DRIFT,
            summary = when {
                mountNamespaceResult.signalCount > 0 && mountNamespaceResult.mountAnchorDriftCount > 0 ->
                    "${mountNamespaceResult.mountAnchorDriftCount} anchor(s)"

                mountNamespaceResult.signalCount > 0 -> "${mountNamespaceResult.signalCount} drift hit(s)"
                mountNamespaceResult.isolatedProcessAvailable -> "Clean"
                mountNamespaceResult.available -> "Unavailable"
                else -> "Unavailable"
            },
            outcome = when {
                mountNamespaceResult.signalCount > 0 -> NativeRootMethodOutcome.WARNING
                mountNamespaceResult.isolatedProcessAvailable -> NativeRootMethodOutcome.CLEAN
                else -> NativeRootMethodOutcome.SUPPORT
            },
            detail = buildString {
                append("Compares the main app process against an isolated helper process using /proc/self/ns/mnt plus /apex, /system, and /vendor mount anchors. This is an ordinary-app-safe way to look for KSU profile mount namespace drift.")
                if (mountNamespaceResult.detail.isNotBlank()) {
                    append("\n")
                    append(mountNamespaceResult.detail)
                }
            },
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.KSU_MANAGER_FINGERPRINT,
            summary = when {
                managerFingerprintResult.packagePresent && managerFingerprintResult.traitHitCount > 0 ->
                    "${managerFingerprintResult.traitHitCount}/3 traits"

                managerFingerprintResult.packagePresent -> "Present"
                managerFingerprintResult.visibilityRestricted -> "Scoped"
                managerFingerprintResult.visibilityUnknown -> "Unavailable"
                managerFingerprintResult.available -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                managerFingerprintResult.packagePresent -> NativeRootMethodOutcome.WARNING
                managerFingerprintResult.visibilityRestricted || managerFingerprintResult.visibilityUnknown ->
                    NativeRootMethodOutcome.SUPPORT
                managerFingerprintResult.available -> NativeRootMethodOutcome.CLEAN
                else -> NativeRootMethodOutcome.SUPPORT
            },
            detail = buildString {
                append("Reads the public manager manifest for zygotePreloadName, isolatedProcess, and useAppZygote traits under the well-known KernelSU package name. This is auxiliary only because package visibility, repackaging, or renamed managers can change it.")
                if (managerFingerprintResult.detail.isNotBlank()) {
                    append("\n")
                    append(managerFingerprintResult.detail)
                }
            },
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.KSU_THRONE_HUNT,
            summary = when {
                throneHuntResult.hitCount > 0 -> "${throneHuntResult.hitCount} hit(s)"
                !throneHuntResult.available -> throneHuntResult.failureStage
                throneHuntResult.watchDenied -> "Watch denied"
                else -> "Clean"
            },
            outcome = when {
                throneHuntResult.hitCount > 0 -> NativeRootMethodOutcome.DETECTED
                !throneHuntResult.available -> NativeRootMethodOutcome.SUPPORT
                throneHuntResult.watchDenied -> NativeRootMethodOutcome.SUPPORT
                else -> NativeRootMethodOutcome.CLEAN
            },
            detail = buildString {
                append("Rewrites /data/system/packages.list through the zero-permission setMimeGroup path ")
                append("and watches the app's own /data/app package directory from the app_zygote carrier. ")
                append("KernelSU's pkg_observer reacts to the packages.list rewrite by running ")
                append("track_throne -> search_manager(\"/data/app\", 2), which opens and iterates our package ")
                append("directory inode; that traversal is what the inherited watch reports.\n")
                append("collection=")
                append(throneHuntResult.collection.outcome.name)
                append("\nfailureStage=")
                append(throneHuntResult.failureStage)
                append("\nopen=")
                append(throneHuntResult.directoryOpenCount)
                append(" access=")
                append(throneHuntResult.directoryAccessCount)
                append(" raw=")
                append(throneHuntResult.rawEventCount)
                append(" invalid=")
                append(throneHuntResult.invalidEventCount)
                append(" baseline=")
                append(throneHuntResult.baselineHitCount)
                append("\nstimulus=")
                append(throneHuntResult.stimulusDetail)
                append('\n')
                if (throneHuntResult.detail.isNotBlank()) {
                    append(throneHuntResult.detail)
                }
            },
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.RUNTIME_ARTIFACTS,
            summary = when {
                runtimeFindings.isNotEmpty() -> "${runtimeFindings.size} hit(s)"
                snapshot.available -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                runtimeFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> NativeRootMethodOutcome.DETECTED
                runtimeFindings.isNotEmpty() -> NativeRootMethodOutcome.WARNING
                snapshot.available -> NativeRootMethodOutcome.CLEAN
                else -> NativeRootMethodOutcome.SUPPORT
            },
            detail = buildString {
                append("Scan /data/adb manager paths, curated tmp/system/storage residue paths, /data/local/tmp metadata, /proc process state, per-UID cgroup trees, isolated-process mount drift, and weak KernelSU manager manifest fingerprints for KernelSU, APatch, KernelPatch, Magisk, selective hiding, and unexpected root-process traces.")
                if (shellTmpDetail.isNotBlank()) {
                    append("\nShell tmp: ")
                    append(shellTmpDetail)
                }
                if (rootProcessDetail.isNotBlank()) {
                    append("\nProcess audit: ")
                    append(rootProcessDetail)
                }
                if (cgroupResult.detail.isNotBlank()) {
                    append("\nCgroup audit: ")
                    append(cgroupResult.detail)
                }
                if (mountNamespaceResult.detail.isNotBlank()) {
                    append("\nMount drift: ")
                    append(mountNamespaceResult.detail)
                }
                if (managerFingerprintResult.detail.isNotBlank()) {
                    append("\nManager fingerprint: ")
                    append(managerFingerprintResult.detail)
                }
            },
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.CGROUP_LEAKAGE,
            summary = when {
                cgroupResult.hitCount > 0 -> "${cgroupResult.hitCount} hit(s)"
                cgroupResult.available -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                cgroupResult.findings.any { it.severity == NativeRootFindingSeverity.DANGER } -> NativeRootMethodOutcome.DETECTED
                cgroupResult.hitCount > 0 -> NativeRootMethodOutcome.WARNING
                cgroupResult.available -> NativeRootMethodOutcome.CLEAN
                else -> NativeRootMethodOutcome.SUPPORT
            },
            detail = "Enumerate per-UID cgroup trees and compare native getdents visibility against Java File view, /proc/<pid>/status UID ownership, and PID liveness syscalls such as kill/getsid/getpgid/sched_getscheduler/pidfd_open. ${cgroupResult.detail}".trim(),
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.KERNEL_TRACES,
            summary = when {
                kernelFindings.isNotEmpty() -> "${kernelFindings.size} source(s)"
                snapshot.available -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                kernelFindings.isNotEmpty() -> NativeRootMethodOutcome.WARNING
                snapshot.available -> NativeRootMethodOutcome.CLEAN
                else -> NativeRootMethodOutcome.SUPPORT
            },
            detail = "Check /proc/kallsyms, /proc/modules, and uname strings for KernelSU, APatch, KernelPatch, SuperCall, or Magisk tokens.",
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.PROPERTY_RESIDUE,
            summary = when {
                propertyFindings.isNotEmpty() -> "${propertyFindings.size} hit(s)"
                snapshot.available -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                propertyFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> NativeRootMethodOutcome.DETECTED
                propertyFindings.isNotEmpty() -> NativeRootMethodOutcome.WARNING
                snapshot.available -> NativeRootMethodOutcome.CLEAN
                else -> NativeRootMethodOutcome.SUPPORT
            },
            detail = "Read a small catalog of root-specific properties such as ro.kernel.ksu and APatch/KernelPatch variants.",
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.TEMP_ROOT_ARTIFACTS,
            summary = when {
                tempRootArtifactResult.cveExploitDetected -> "CVE-2026-43499"
                tempRootArtifactResult.tempRootDetected -> "${tempRootArtifactResult.hitCount} hit(s)"
                tempRootArtifactResult.available -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                tempRootArtifactResult.tempRootDetected -> NativeRootMethodOutcome.DETECTED
                tempRootArtifactResult.available -> NativeRootMethodOutcome.CLEAN
                else -> NativeRootMethodOutcome.SUPPORT
            },
            detail = "Scans /data/local/tmp for temp root exploit artifacts (ksud, temp_su, ksu-helper, ksu-payload, libcve43499root.so). Files matching the CVE-2026-43499 tooling show it was staged on this device; they do not show whether an escalation succeeded or is still active. Paths this process cannot stat leave the check unavailable.",
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.NATIVE_LIBRARY,
            summary = if (snapshot.available) "Loaded" else "Unavailable",
            outcome = if (snapshot.available) NativeRootMethodOutcome.CLEAN else NativeRootMethodOutcome.SUPPORT,
            detail = "JNI-backed native root detection module.",
        ),
        NativeRootMethodResult(
            method = NativeRootMethod.SIGNAL_SUMMARY,
            summary = when {
                directFindings.isNotEmpty() -> "${directFindings.size} direct"
                findings.isNotEmpty() -> "${findings.size} indirect"
                snapshot.available -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                directFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> NativeRootMethodOutcome.DETECTED
                findings.isNotEmpty() -> NativeRootMethodOutcome.WARNING
                snapshot.available -> NativeRootMethodOutcome.CLEAN
                else -> NativeRootMethodOutcome.SUPPORT
            },
            detail = "Direct probes are syscall and side-channel results; indirect probes are kernel strings, paths, processes, properties, and cgroup leakage.",
        ),
    )
}
