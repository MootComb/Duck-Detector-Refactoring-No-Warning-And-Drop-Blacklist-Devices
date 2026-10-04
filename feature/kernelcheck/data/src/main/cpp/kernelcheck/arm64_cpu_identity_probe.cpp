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

#include "kernelcheck/arm64_cpu_identity_probe.h"

#include "kernelcheck/arm64_cached_cpu_identity.h"

#include <csetjmp>
#include <csignal>
#include <iomanip>
#include <pthread.h>
#include <sched.h>
#include <sstream>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__aarch64__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

namespace duckdetector::kernelcheck {

    namespace {

#if defined(__aarch64__)
        // Reads that must agree before a value is attributed to the pinned CPU, and the reads one
        // CPU may take in total while its thread keeps being moved off it.
        constexpr int kAgreeingReadsRequired = 3;
        constexpr int kMaxReadsPerCpu = 8;

        pthread_mutex_t g_sigill_mutex = PTHREAD_MUTEX_INITIALIZER;
        thread_local sigjmp_buf *g_sigill_jump_buffer = nullptr;
        struct sigaction g_previous_sigill_action{};

        void forward_sigill(int signal_number, siginfo_t *info, void *context) {
            if ((g_previous_sigill_action.sa_flags & SA_SIGINFO) != 0 &&
                g_previous_sigill_action.sa_sigaction != nullptr) {
                g_previous_sigill_action.sa_sigaction(signal_number, info, context);
                return;
            }

            if (g_previous_sigill_action.sa_handler == SIG_IGN) {
                return;
            }
            if (g_previous_sigill_action.sa_handler != SIG_DFL &&
                g_previous_sigill_action.sa_handler != nullptr) {
                g_previous_sigill_action.sa_handler(signal_number);
                return;
            }

            sigaction(SIGILL, &g_previous_sigill_action, nullptr);
            raise(SIGILL);
        }

        void sigill_handler(int signal_number, siginfo_t *info, void *context) {
            if (g_sigill_jump_buffer != nullptr) {
                siglongjmp(*g_sigill_jump_buffer, 1);
            }
            forward_sigill(signal_number, info, context);
        }

        /**
         * Reads MIDR_EL1 through the kernel's EL0 MRS emulation.
         *
         * This comparison is only meaningful because MIDR_EL1 is the exception among the emulated
         * registers. Documentation/arm64/cpu-feature-registers.rst states that a visible field
         * "holds the system wide safe value for the particular feature (except for MIDR_EL1)", and
         * for MIDR_EL1 specifically that it "will contain the value as available on the CPU where it
         * is fetched and is not a system wide safe value". So this tracks the core the thread is
         * pinned to, which is why the caller sets affinity first -- the same document warns the read
         * is otherwise racy against migration. The ID_AA64* registers must not be used this way:
         * they are sanitised system-wide values and would compare equal on every core by design.
         *
         * SIGILL is still handled because the access is architecturally undefined at EL0 and the
         * emulation is what makes it work; a kernel lacking it delivers the signal instead.
         */
        bool read_midr_safely(std::uint32_t *midr) {
            if (midr == nullptr || pthread_mutex_lock(&g_sigill_mutex) != 0) {
                return false;
            }

            struct sigaction action{};
            action.sa_sigaction = sigill_handler;
            action.sa_flags = SA_SIGINFO;
            sigemptyset(&action.sa_mask);
            if (sigaction(SIGILL, &action, &g_previous_sigill_action) != 0) {
                pthread_mutex_unlock(&g_sigill_mutex);
                return false;
            }

            bool succeeded = false;
            sigjmp_buf jump_buffer;
            g_sigill_jump_buffer = &jump_buffer;
            if (sigsetjmp(jump_buffer, 1) == 0) {
                std::uint64_t value = 0;
                __asm__ volatile("mrs %0, MIDR_EL1" : "=r"(value));
                *midr = static_cast<std::uint32_t>(value);
                succeeded = true;
            }
            g_sigill_jump_buffer = nullptr;
            sigaction(SIGILL, &g_previous_sigill_action, nullptr);
            pthread_mutex_unlock(&g_sigill_mutex);
            return succeeded;
        }

        bool is_running_on(int cpu) {
            unsigned current = 0;
            return syscall(__NR_getcpu, &current, nullptr, nullptr) == 0 &&
                   current == static_cast<unsigned>(cpu);
        }

        /**
         * sched_setaffinity() returns once the thread runs on the target CPU, but nothing keeps it
         * there. Moving the process to another cpuset, which Android does as the app changes
         * between top-app, foreground and background, resets the affinity of every thread moved
         * (cpuset_attach() in kernel/cgroup/cpuset.c; 6.6 keeps the requested mask only where it
         * intersects the new cpuset, 6.1 drops it), and pausing or offlining a CPU pushes the
         * tasks pinned to it elsewhere (select_fallback_rq() in kernel/sched/core.c). The MRS
         * emulation runs preemptibly as well, so its value belongs to whichever CPU executes it,
         * and on a heterogeneous SoC a moved read would be compared with another core's cached
         * identity. A read therefore counts only when getcpu() reports the pinned CPU both before
         * and after it.
         */
        void read_pinned_midr(
                const cpu_set_t &target_affinity,
                CpuIdentityObservation *observation
        ) {
            std::optional<std::uint32_t> agreed_midr;
            int agreeing_reads = 0;
            for (int attempt = 0;
                 attempt < kMaxReadsPerCpu && agreeing_reads < kAgreeingReadsRequired;
                 ++attempt) {
                const bool started_on_cpu = is_running_on(observation->cpu);
                std::uint32_t midr = 0;
                if (!read_midr_safely(&midr)) {
                    observation->mrs_state = MrsReadState::Faulted;
                    return;
                }
                if (!started_on_cpu || !is_running_on(observation->cpu)) {
                    ++observation->reads_off_cpu;
                    if (sched_setaffinity(0, sizeof(target_affinity), &target_affinity) != 0) {
                        break;
                    }
                    continue;
                }
                if (agreed_midr && *agreed_midr != midr) {
                    observation->mrs_state = MrsReadState::Unstable;
                    return;
                }
                agreed_midr = midr;
                ++agreeing_reads;
            }
            if (agreeing_reads < kAgreeingReadsRequired) {
                observation->mrs_state = MrsReadState::Unattributed;
                return;
            }
            observation->mrs_midr = agreed_midr;
            observation->mrs_state = MrsReadState::Verified;
        }
#endif

        const char *status_name(CpuIdentityProbeStatus status) {
            switch (status) {
                case CpuIdentityProbeStatus::Completed:
                    return "COMPLETED";
                case CpuIdentityProbeStatus::UnsupportedAbi:
                    return "UNSUPPORTED_ABI";
                case CpuIdentityProbeStatus::AffinityUnavailable:
                    return "AFFINITY_UNAVAILABLE";
                case CpuIdentityProbeStatus::CpuidEmulationUnavailable:
                    return "CPUID_EMULATION_UNAVAILABLE";
            }
            return "AFFINITY_UNAVAILABLE";
        }

        const char *source_name(CachedCpuIdentitySource source) {
            switch (source) {
                case CachedCpuIdentitySource::None:
                    return "NONE";
                case CachedCpuIdentitySource::Sysfs:
                    return "SYSFS";
                case CachedCpuIdentitySource::ProcCpuinfo:
                    return "PROC_CPUINFO";
            }
            return "NONE";
        }

        const char *mrs_state_name(MrsReadState state) {
            switch (state) {
                case MrsReadState::NotAttempted:
                    return "NOT_ATTEMPTED";
                case MrsReadState::Verified:
                    return "VERIFIED";
                case MrsReadState::Unattributed:
                    return "UNATTRIBUTED";
                case MrsReadState::Unstable:
                    return "UNSTABLE";
                case MrsReadState::Faulted:
                    return "FAULTED";
            }
            return "NOT_ATTEMPTED";
        }

        std::string format_midr(const std::optional<std::uint32_t> &midr) {
            if (!midr) {
                return "NA";
            }
            std::ostringstream output;
            output << std::hex << std::nouppercase << std::setw(8) << std::setfill('0') << *midr;
            return output.str();
        }

    }  // namespace

    CpuIdentityProbeResult collect_arm64_cpu_identity() {
        CpuIdentityProbeResult result;
#if defined(__aarch64__)
        cpu_set_t original_affinity;
        CPU_ZERO(&original_affinity);
        if (sched_getaffinity(0, sizeof(original_affinity), &original_affinity) != 0) {
            result.status = CpuIdentityProbeStatus::AffinityUnavailable;
            return result;
        }

        // Documentation/arm64/cpu-feature-registers.rst: reading MIDR_EL1 from EL0 works only
        // through the kernel's MRS emulation, which is advertised by HWCAP_CPUID; where it is
        // absent the access stays undefined and is delivered as SIGILL. Consulting the capability
        // bit keeps "this kernel exposes no CPUID emulation" distinct from "the read failed", and
        // avoids provoking a SIGILL on every core to rediscover what the kernel already states.
        const bool cpuid_emulation_available = (getauxval(AT_HWCAP) & HWCAP_CPUID) != 0;
        result.status = cpuid_emulation_available
                        ? CpuIdentityProbeStatus::Completed
                        : CpuIdentityProbeStatus::CpuidEmulationUnavailable;

        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
            if (!CPU_ISSET(cpu, &original_affinity)) {
                continue;
            }

            CpuIdentityObservation observation;
            observation.cpu = cpu;
            cpu_set_t target_affinity;
            CPU_ZERO(&target_affinity);
            CPU_SET(cpu, &target_affinity);
            observation.affinity_succeeded =
                    sched_setaffinity(0, sizeof(target_affinity), &target_affinity) == 0;
            if (observation.affinity_succeeded) {
                // The cached identity is still collected without MRS emulation, so the report can
                // show what each core reports even when no register read is possible.
                collect_cached_cpu_identity(&observation);
                if (cpuid_emulation_available) {
                    read_pinned_midr(target_affinity, &observation);
                }
            }
            result.observations.push_back(observation);
        }

        sched_setaffinity(0, sizeof(original_affinity), &original_affinity);
#else
        result.status = CpuIdentityProbeStatus::UnsupportedAbi;
#endif
        return result;
    }

    std::string encode_arm64_cpu_identity(const CpuIdentityProbeResult &result) {
        std::ostringstream output;
        output << "CPU_IDENTITY_STATUS=" << status_name(result.status) << '\n';
        for (const CpuIdentityObservation &observation: result.observations) {
            output << "CPU_IDENTITY="
                   << observation.cpu << '\t'
                   << (observation.affinity_succeeded ? "1" : "0") << '\t'
                   << source_name(observation.cached_source) << '\t'
                   << format_midr(observation.cached_midr) << '\t'
                   << format_midr(observation.mrs_midr) << '\t'
                   << mrs_state_name(observation.mrs_state) << '\t'
                   << observation.reads_off_cpu << '\n';
        }
        return output.str();
    }

}  // namespace duckdetector::kernelcheck
