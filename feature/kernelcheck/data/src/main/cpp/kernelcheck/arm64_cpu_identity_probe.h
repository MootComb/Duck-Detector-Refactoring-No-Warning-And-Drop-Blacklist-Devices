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

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace duckdetector::kernelcheck {

    enum class CpuIdentityProbeStatus {
        Completed,
        UnsupportedAbi,
        AffinityUnavailable,
        /**
         * The kernel does not advertise HWCAP_CPUID, so the EL0 MRS emulation that makes MIDR_EL1
         * readable from userspace is absent and no per-CPU register read can succeed.
         */
        CpuidEmulationUnavailable,
    };

    enum class CachedCpuIdentitySource {
        None,
        Sysfs,
        ProcCpuinfo,
    };

    /** Whether the emulated MIDR_EL1 reads of one CPU produced a value that belongs to that CPU. */
    enum class MrsReadState {
        /** No read was made: the pin failed or the kernel offers no MRS emulation. */
        NotAttempted,
        /** Every read ran on the pinned CPU, as getcpu() reported around it, and they agreed. */
        Verified,
        /** Too few reads could be shown to run on the pinned CPU. */
        Unattributed,
        /** Reads that ran on the pinned CPU returned different values. */
        Unstable,
        /** The MRS itself failed. */
        Faulted,
    };

    struct CpuIdentityObservation {
        int cpu = -1;
        bool affinity_succeeded = false;
        CachedCpuIdentitySource cached_source = CachedCpuIdentitySource::None;
        std::optional<std::uint32_t> cached_midr;
        /** Set only when mrs_state is Verified. */
        std::optional<std::uint32_t> mrs_midr;
        MrsReadState mrs_state = MrsReadState::NotAttempted;
        /** Reads discarded because getcpu() did not report the pinned CPU on both sides of them. */
        int reads_off_cpu = 0;
    };

    struct CpuIdentityProbeResult {
        CpuIdentityProbeStatus status = CpuIdentityProbeStatus::UnsupportedAbi;
        std::vector<CpuIdentityObservation> observations;
    };

    CpuIdentityProbeResult collect_arm64_cpu_identity();

    std::string encode_arm64_cpu_identity(const CpuIdentityProbeResult &result);

}  // namespace duckdetector::kernelcheck
