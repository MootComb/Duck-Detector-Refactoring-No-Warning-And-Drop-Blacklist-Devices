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

package com.eltavine.duckdetector.features.selinux.data.repository

import android.os.Build
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import java.io.File
import java.util.concurrent.TimeUnit

internal fun checkSelinuxFilesystem(): SelinuxCheckResult {
    return try {
        val mount = File(SELINUX_MOUNT_PATH)
        val policy = File(SELINUX_POLICY_PATH)
        val enforce = File(SELINUX_STATUS_PATH)
        when {
            !mount.exists() -> SelinuxCheckResult(
                method = METHOD_FILESYSTEM,
                status = FILESYSTEM_NOT_MOUNTED,
                isSecure = false,
                permissionDenied = false,
                details = "/sys/fs/selinux does not exist",
            )

            policy.exists() && enforce.exists() -> SelinuxCheckResult(
                method = METHOD_FILESYSTEM,
                status = FILESYSTEM_ACTIVE,
                isSecure = true,
                permissionDenied = false,
                details = "SELinux filesystem mounted with policy nodes",
            )

            else -> SelinuxCheckResult(
                method = METHOD_FILESYSTEM,
                status = FILESYSTEM_MOUNTED,
                isSecure = true,
                permissionDenied = false,
                details = "SELinux filesystem present",
            )
        }
    } catch (throwable: Throwable) {
        SelinuxCheckResult(
            method = METHOD_FILESYSTEM,
            status = "Error",
            isSecure = null,
            permissionDenied = false,
            details = throwable.message ?: "Filesystem check failed",
        )
    }
}

internal fun checkViaSysfs(): SelinuxCheckResult {
    return try {
        val enforceFile = File(SELINUX_STATUS_PATH)
        when {
            enforceFile.exists() && enforceFile.canRead() -> {
                when (enforceFile.readText().trim()) {
                    "1" -> SelinuxCheckResult(
                        method = METHOD_SYSFS,
                        status = SELINUX_ENFORCING,
                        isSecure = true,
                        permissionDenied = false,
                        details = "/sys/fs/selinux/enforce = 1",
                    )

                    "0" -> SelinuxCheckResult(
                        method = METHOD_SYSFS,
                        status = SELINUX_PERMISSIVE,
                        isSecure = false,
                        permissionDenied = false,
                        details = "/sys/fs/selinux/enforce = 0",
                    )

                    else -> SelinuxCheckResult(
                        method = METHOD_SYSFS,
                        status = "Unknown",
                        isSecure = null,
                        permissionDenied = false,
                        details = "Unexpected sysfs value",
                    )
                }
            }

            enforceFile.exists() && !enforceFile.canRead() -> SelinuxCheckResult(
                method = METHOD_SYSFS,
                status = BLOCKED_ENFORCING,
                isSecure = true,
                permissionDenied = true,
                details = "enforce file present but unreadable",
            )

            else -> SelinuxCheckResult(
                method = METHOD_SYSFS,
                status = "Not found",
                isSecure = null,
                permissionDenied = false,
                details = "enforce file does not exist",
            )
        }
    } catch (securityException: SecurityException) {
        SelinuxCheckResult(
            method = METHOD_SYSFS,
            status = BLOCKED_ENFORCING,
            isSecure = true,
            permissionDenied = true,
            details = "Access blocked by SELinux policy",
        )
    } catch (throwable: Throwable) {
        if (throwable.message.isPermissionDenied()) {
            SelinuxCheckResult(
                method = METHOD_SYSFS,
                status = BLOCKED_ENFORCING,
                isSecure = true,
                permissionDenied = true,
                details = "Access blocked by SELinux policy",
            )
        } else {
            SelinuxCheckResult(
                method = METHOD_SYSFS,
                status = "Error",
                isSecure = null,
                permissionDenied = false,
                details = throwable.message ?: "sysfs check failed",
            )
        }
    }
}

internal fun checkViaGetenforce(): SelinuxCheckResult {
    var process: Process? = null
    return try {
        process = ProcessBuilder("getenforce")
            .redirectErrorStream(false)
            .start()

        val stdout = process.inputStream.bufferedReader().use { it.readText().trim() }
        val stderr = process.errorStream.bufferedReader().use { it.readText().trim() }
        val completed = process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        if (!completed) {
            process.destroyForcibly()
            return SelinuxCheckResult(
                method = METHOD_GETENFORCE,
                status = "Timeout",
                isSecure = null,
                permissionDenied = false,
                details = "Command timed out after ${PROCESS_TIMEOUT_SECONDS}s",
            )
        }

        when {
            stdout.equals(SELINUX_ENFORCING, ignoreCase = true) -> SelinuxCheckResult(
                method = METHOD_GETENFORCE,
                status = SELINUX_ENFORCING,
                isSecure = true,
                permissionDenied = false,
                details = "Command returned Enforcing",
            )

            stdout.equals(SELINUX_PERMISSIVE, ignoreCase = true) -> SelinuxCheckResult(
                method = METHOD_GETENFORCE,
                status = SELINUX_PERMISSIVE,
                isSecure = false,
                permissionDenied = false,
                details = "Command returned Permissive",
            )

            stdout.equals(SELINUX_DISABLED, ignoreCase = true) -> SelinuxCheckResult(
                method = METHOD_GETENFORCE,
                status = SELINUX_DISABLED,
                isSecure = false,
                permissionDenied = false,
                details = "Command returned Disabled",
            )

            stderr.isPermissionDenied() -> SelinuxCheckResult(
                method = METHOD_GETENFORCE,
                status = BLOCKED_ENFORCING,
                isSecure = true,
                permissionDenied = true,
                details = "Command blocked by SELinux policy",
            )

            stderr.isNotBlank() -> SelinuxCheckResult(
                method = METHOD_GETENFORCE,
                status = "Error",
                isSecure = null,
                permissionDenied = false,
                details = "stderr: $stderr",
            )

            stdout.isBlank() -> SelinuxCheckResult(
                method = METHOD_GETENFORCE,
                status = "No output",
                isSecure = null,
                permissionDenied = false,
                details = "Command returned empty",
            )

            else -> SelinuxCheckResult(
                method = METHOD_GETENFORCE,
                status = "Unknown",
                isSecure = null,
                permissionDenied = false,
                details = "Unexpected: $stdout",
            )
        }
    } catch (throwable: Throwable) {
        if (throwable.message.isPermissionDenied()) {
            SelinuxCheckResult(
                method = METHOD_GETENFORCE,
                status = BLOCKED_ENFORCING,
                isSecure = true,
                permissionDenied = true,
                details = "Execution blocked by SELinux",
            )
        } else {
            SelinuxCheckResult(
                method = METHOD_GETENFORCE,
                status = "Failed",
                isSecure = null,
                permissionDenied = false,
                details = throwable.message ?: "getenforce failed",
            )
        }
    } finally {
        process?.destroy()
    }
}

internal fun checkViaProcAttr(): SelinuxCheckResult {
    return try {
        val procAttrFile = File(PROC_ATTR_PATH)
        if (procAttrFile.exists() && procAttrFile.canRead()) {
            val context = procAttrFile.readText().trim().replace("\u0000", "")
            if (context.isBlank()) {
                SelinuxCheckResult(
                    method = METHOD_PROC_ATTR,
                    status = "Empty",
                    isSecure = null,
                    permissionDenied = false,
                    details = "Context file empty",
                )
            } else {
                val type = context.split(":").getOrNull(2) ?: "unknown"
                when {
                    type == "untrusted_app" || type.contains(
                        "app",
                        ignoreCase = true
                    ) -> SelinuxCheckResult(
                        method = METHOD_PROC_ATTR,
                        status = SELINUX_ENFORCING,
                        isSecure = true,
                        permissionDenied = false,
                        details = "Context: $context (confined to $type)",
                    )

                    type == "kernel" || type == "init" -> SelinuxCheckResult(
                        method = METHOD_PROC_ATTR,
                        status = "System context",
                        isSecure = true,
                        permissionDenied = false,
                        details = "Context: $context",
                    )

                    context.contains(":") -> SelinuxCheckResult(
                        method = METHOD_PROC_ATTR,
                        status = SELINUX_ENFORCING,
                        isSecure = true,
                        permissionDenied = false,
                        details = "Context: $context",
                    )

                    else -> SelinuxCheckResult(
                        method = METHOD_PROC_ATTR,
                        status = "Unknown context",
                        isSecure = null,
                        permissionDenied = false,
                        details = "Raw: $context",
                    )
                }
            }
        } else {
            SelinuxCheckResult(
                method = METHOD_PROC_ATTR,
                status = "Not readable",
                isSecure = null,
                permissionDenied = !procAttrFile.exists(),
                details = if (procAttrFile.exists()) "Access denied" else "File not found",
            )
        }
    } catch (securityException: SecurityException) {
        SelinuxCheckResult(
            method = METHOD_PROC_ATTR,
            status = "Blocked",
            isSecure = null,
            permissionDenied = true,
            details = securityException.message ?: "SecurityException",
        )
    } catch (throwable: Throwable) {
        SelinuxCheckResult(
            method = METHOD_PROC_ATTR,
            status = "Error",
            isSecure = null,
            permissionDenied = false,
            details = throwable.message ?: "proc attr check failed",
        )
    }
}

internal fun determineStatusWithParadoxLogic(
    results: List<SelinuxCheckResult>,
): StatusResolution {
    val filesystemActive = results.any {
        it.method == METHOD_FILESYSTEM && (it.status == FILESYSTEM_ACTIVE || it.status == FILESYSTEM_MOUNTED)
    }

    results.forEach { result ->
        if (result.status == SELINUX_PERMISSIVE) {
            return StatusResolution(
                SelinuxMode.PERMISSIVE,
                SELINUX_PERMISSIVE,
                paradoxDetected = false
            )
        }
        if (result.status == SELINUX_DISABLED || result.status == FILESYSTEM_NOT_MOUNTED) {
            return StatusResolution(
                SelinuxMode.DISABLED,
                SELINUX_DISABLED,
                paradoxDetected = false
            )
        }
    }

    if (results.any { it.status == SELINUX_ENFORCING }) {
        return StatusResolution(
            SelinuxMode.ENFORCING,
            SELINUX_ENFORCING,
            paradoxDetected = false
        )
    }

    val hasPermissionDenied = results.any { it.permissionDenied }
    if (hasPermissionDenied && filesystemActive) {
        return StatusResolution(
            SelinuxMode.ENFORCING,
            "Enforcing (paradox)",
            paradoxDetected = true
        )
    }

    if (filesystemActive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
        return StatusResolution(
            SelinuxMode.ENFORCING,
            "Enforcing (default)",
            paradoxDetected = false
        )
    }

    return StatusResolution(SelinuxMode.UNKNOWN, "Unknown", paradoxDetected = false)
}

private fun String?.isPermissionDenied(): Boolean {
    return this?.contains("Permission denied", ignoreCase = true) == true ||
            this?.contains("EACCES", ignoreCase = true) == true
}

internal data class StatusResolution(
    val mode: SelinuxMode,
    val label: String,
    val paradoxDetected: Boolean,
)

private const val PROCESS_TIMEOUT_SECONDS = 5L
private const val SELINUX_ENFORCING = "Enforcing"
private const val SELINUX_PERMISSIVE = "Permissive"
internal const val SELINUX_DISABLED = "Disabled"
private const val BLOCKED_ENFORCING = "Blocked (Enforcing)"
internal const val METHOD_FILESYSTEM = "filesystem"
private const val METHOD_SYSFS = "sysfs"
private const val METHOD_GETENFORCE = "getenforce"
private const val METHOD_PROC_ATTR = "proc/self/attr"
internal const val FILESYSTEM_NOT_MOUNTED = "Not mounted"
internal const val FILESYSTEM_ACTIVE = "Active"
internal const val FILESYSTEM_MOUNTED = "Mounted"
private const val SELINUX_STATUS_PATH = "/sys/fs/selinux/enforce"
private const val SELINUX_MOUNT_PATH = "/sys/fs/selinux"
private const val SELINUX_POLICY_PATH = "/sys/fs/selinux/policy"
internal const val PROC_ATTR_PATH = "/proc/self/attr/current"
