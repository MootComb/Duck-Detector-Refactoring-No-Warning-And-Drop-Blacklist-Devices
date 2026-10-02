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

package com.eltavine.duckdetector.features.kernelcheck.data.native

enum class Arm64CpuIdentityProbeStatus {
    COMPLETED,
    UNSUPPORTED_ABI,
    AFFINITY_UNAVAILABLE,

    /**
     * The kernel does not advertise HWCAP_CPUID, so the EL0 MRS emulation that exposes MIDR_EL1 is
     * absent and the comparison cannot run on this kernel at all.
     */
    CPUID_EMULATION_UNAVAILABLE,
    UNKNOWN,
}

enum class CachedCpuIdentitySource {
    SYSFS,
    PROC_CPUINFO,
    NONE,
}

/**
 * Whether the native probe could attribute its MIDR_EL1 reads to the CPU it pinned the thread to.
 * Only [VERIFIED] reads are compared: the others mean the thread was moved off the CPU, reads on
 * the CPU disagreed, or no value was read, none of which says anything about the kernel's cached
 * identity.
 */
enum class MrsReadState {
    VERIFIED,
    NOT_ATTEMPTED,
    UNATTRIBUTED,
    UNSTABLE,
    FAULTED,
    UNKNOWN,
}

data class Arm64CpuIdentityObservation(
    val cpu: Int,
    val affinitySucceeded: Boolean,
    val cachedSource: CachedCpuIdentitySource,
    val cachedMidr: Long?,
    val mrsMidr: Long?,
    val mrsReadState: MrsReadState,
    /** Reads the probe discarded because getcpu() did not report the pinned CPU around them. */
    val readsOffCpu: Int,
)

internal object Arm64CpuIdentityPayloadCodec {

    fun parseStatus(value: String?): Arm64CpuIdentityProbeStatus {
        return runCatching {
            Arm64CpuIdentityProbeStatus.valueOf(value.orEmpty())
        }.getOrDefault(Arm64CpuIdentityProbeStatus.UNKNOWN)
    }

    fun parseObservation(value: String): Arm64CpuIdentityObservation? {
        val fields = value.split('\t')
        if (fields.size != FIELD_COUNT) {
            return null
        }

        val cpu = fields[0].toIntOrNull()?.takeIf { it >= 0 } ?: return null
        val affinitySucceeded = when (fields[1]) {
            "1" -> true
            "0" -> false
            else -> return null
        }
        val source = runCatching {
            CachedCpuIdentitySource.valueOf(fields[2])
        }.getOrNull() ?: return null
        val cachedMidr = fields[3].parseMidr()
        if (cachedMidr == null && fields[3] != "NA") {
            return null
        }
        val mrsMidr = fields[4].parseMidr()
        if (mrsMidr == null && fields[4] != "NA") {
            return null
        }
        val mrsReadState = runCatching {
            MrsReadState.valueOf(fields[5])
        }.getOrDefault(MrsReadState.UNKNOWN)
        val readsOffCpu = fields[6].toIntOrNull()?.takeIf { it >= 0 } ?: return null

        return Arm64CpuIdentityObservation(
            cpu = cpu,
            affinitySucceeded = affinitySucceeded,
            cachedSource = source,
            cachedMidr = cachedMidr,
            mrsMidr = mrsMidr,
            mrsReadState = mrsReadState,
            readsOffCpu = readsOffCpu,
        )
    }

    private fun String.parseMidr(): Long? {
        if (this == "NA") {
            return null
        }
        return toLongOrNull(radix = 16)?.takeIf { it in 0..UINT32_MAX }
    }

    private const val FIELD_COUNT = 7
    private const val UINT32_MAX = 0xffff_ffffL
}
