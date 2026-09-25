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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import java.io.FileOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.Locale

public data class SelinuxProcAttrCurrentResult(
    val label: String,
    val targetContext: String,
    val outcomeClass: String,
    val rawMessage: String,
) {
    public fun detected(): Boolean {
        return outcomeClass == OUTCOME_SUCCESS ||
            outcomeClass == OUTCOME_DETECTED_NON_EINVAL ||
            outcomeClass == OUTCOME_DETECTED_SECURITY_EXCEPTION
    }

    public companion object {
        public const val OUTCOME_SUCCESS: String = "SUCCESS"
        public const val OUTCOME_NORMAL_EINVAL: String = "NORMAL_EINVAL"
        public const val OUTCOME_DETECTED_NON_EINVAL: String = "DETECTED_NON_EINVAL"
        public const val OUTCOME_DETECTED_SECURITY_EXCEPTION: String = "DETECTED_SECURITY_EXCEPTION"
    }
}

public class SelinuxProcAttrCurrentProbe {

    public fun inspect(): List<SelinuxProcAttrCurrentResult> {
        return TARGETS.map { target ->
            runProbe(target.label, target.context)
        }
    }

    private fun runProbe(
        label: String,
        targetContext: String,
    ): SelinuxProcAttrCurrentResult {
        return try {
            val payload = targetContext.toByteArray(StandardCharsets.UTF_8)
            FileOutputStream(PROC_ATTR_CURRENT_PATH).use { out ->
                Os.write(out.fd, payload, 0, payload.size)
            }
            SelinuxProcAttrCurrentResult(
                label = label,
                targetContext = targetContext,
                outcomeClass = SelinuxProcAttrCurrentResult.OUTCOME_SUCCESS,
                rawMessage = "write succeeded",
            )
        } catch (error: SecurityException) {
            SelinuxProcAttrCurrentResult(
                label = label,
                targetContext = targetContext,
                outcomeClass = SelinuxProcAttrCurrentResult.OUTCOME_DETECTED_SECURITY_EXCEPTION,
                rawMessage = "${PlatformFailureName.of(error)}: ${error.message}",
            )
        } catch (error: IOException) {
            classifyIOException(label, targetContext, error)
        } catch (error: ErrnoException) {
            classifyErrnoException(label, targetContext, error)
        }
    }

    private fun classifyIOException(
        label: String,
        targetContext: String,
        error: IOException,
    ): SelinuxProcAttrCurrentResult {
        val detail = "${PlatformFailureName.of(error)}: ${error.message}"
        val outcome = if (
            error.message
                ?.lowercase(Locale.ROOT)
                ?.contains("invalid argument") == true
        ) {
            SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL
        } else {
            SelinuxProcAttrCurrentResult.OUTCOME_DETECTED_NON_EINVAL
        }
        return SelinuxProcAttrCurrentResult(
            label = label,
            targetContext = targetContext,
            outcomeClass = outcome,
            rawMessage = detail,
        )
    }

    private fun classifyErrnoException(
        label: String,
        targetContext: String,
        error: ErrnoException,
    ): SelinuxProcAttrCurrentResult {
        val detail = "${PlatformFailureName.of(error)}: errno=${error.errno}, ${error.message}"
        val outcome = if (error.errno == OsConstants.EINVAL) {
            SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL
        } else {
            SelinuxProcAttrCurrentResult.OUTCOME_DETECTED_NON_EINVAL
        }
        return SelinuxProcAttrCurrentResult(
            label = label,
            targetContext = targetContext,
            outcomeClass = outcome,
            rawMessage = detail,
        )
    }

    private data class ProbeTarget(
        val label: String,
        val context: String,
    )

    public companion object {
        private const val PROC_ATTR_CURRENT_PATH = "/proc/self/attr/current"

        private val TARGETS = listOf(
            ProbeTarget("KernelSU", "u:r:ksu:s0"),
            ProbeTarget("KernelSU file", "u:r:ksu_file:s0"),
            ProbeTarget("Magisk", "u:r:magisk:s0"),
            ProbeTarget("Magisk file", "u:r:magisk_file:s0"),
            ProbeTarget("LSPosed file", "u:r:lsposed_file:s0"),
            ProbeTarget("DroidSpaces daemon", "u:r:droidspacesd:s0"),
            ProbeTarget("MSD app", "u:r:msd_app:s0"),
            ProbeTarget("MSD daemon", "u:r:msd_daemon:s0"),
            ProbeTarget("Xposed data", "u:r:xposed_data:s0"),
        )
    }
}
