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

import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import java.io.File

internal fun checkViaProcAttr(): SelinuxCheckResult {
    return try {
        val procAttrFile = File(PROC_ATTR_PATH)
        if (procAttrFile.exists() && procAttrFile.canRead()) {
            classifyProcAttrContext(procAttrFile.readText())
        } else {
            SelinuxCheckResult(
                method = METHOD_PROC_ATTR,
                status = "Not readable",
                isSecure = null,
                permissionDenied = procAttrFile.exists(),
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

/**
 * The domain this process runs in. The kernel reports a task's context whether or not the policy
 * is enforced (selinux_getprocattr in security/selinux/hooks.c), so a labelled context shows that
 * SELinux is enabled, never whether it enforces.
 */
internal fun classifyProcAttrContext(raw: String): SelinuxCheckResult {
    val context = raw.trim().replace("\u0000", "")
    val type = context.split(":").getOrNull(2)
    return when {
        context.isBlank() -> SelinuxCheckResult(
            method = METHOD_PROC_ATTR,
            status = "Empty",
            isSecure = null,
            permissionDenied = false,
            details = "Context file empty",
        )

        type == null -> SelinuxCheckResult(
            method = METHOD_PROC_ATTR,
            status = "Unknown context",
            isSecure = null,
            permissionDenied = false,
            details = "Raw: $context",
        )

        // Zygote moves every app process into its seapp_contexts domain before app code runs.
        type == "kernel" || type == "init" -> SelinuxCheckResult(
            method = METHOD_PROC_ATTR,
            status = "Unexpected context",
            isSecure = false,
            permissionDenied = false,
            details = "Context: $context. An app process never keeps the $type domain.",
        )

        else -> SelinuxCheckResult(
            method = METHOD_PROC_ATTR,
            status = PROC_ATTR_LABELED,
            isSecure = null,
            permissionDenied = false,
            details = "Context: $context. A labelled context shows SELinux is enabled, not whether it enforces.",
        )
    }
}
