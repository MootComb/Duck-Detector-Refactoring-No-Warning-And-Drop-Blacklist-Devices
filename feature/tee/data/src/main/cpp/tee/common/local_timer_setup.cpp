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

#include "tee/common/local_timer.h"

#include "tee/common/local_timer_internal.h"

#include <sched.h>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>

namespace ducktee::common {

    namespace {

#if defined(__aarch64__)
        using detail::arm64_cntvct_self_check;

        struct SavedThreadAffinity {
            cpu_set_t mask{};
            unsigned int bind_depth = 0;
        };

        thread_local SavedThreadAffinity g_saved_thread_affinity;
#endif

    }  // namespace

    bool bind_current_thread_to_cpu0() {
#if defined(__aarch64__)
#if defined(__NR_gettid)
        const auto tid = static_cast<pid_t>(syscall(__NR_gettid));
#else
        const auto tid = getpid();
#endif
        cpu_set_t cpu0_mask;
        CPU_ZERO(&cpu0_mask);
        CPU_SET(0, &cpu0_mask);

        if (g_saved_thread_affinity.bind_depth == 0 &&
            sched_getaffinity(tid, sizeof(g_saved_thread_affinity.mask),
                              &g_saved_thread_affinity.mask) != 0) {
            return false;
        }
        if (sched_setaffinity(tid, sizeof(cpu0_mask), &cpu0_mask) != 0) {
            return false;
        }
        ++g_saved_thread_affinity.bind_depth;
        return true;
#else
        return false;
#endif
    }

    bool restore_current_thread_affinity() {
#if defined(__aarch64__)
        if (g_saved_thread_affinity.bind_depth == 0) {
            return false;
        }
        if (g_saved_thread_affinity.bind_depth > 1) {
            --g_saved_thread_affinity.bind_depth;
            return true;
        }

#if defined(__NR_gettid)
        const auto tid = static_cast<pid_t>(syscall(__NR_gettid));
#else
        const auto tid = getpid();
#endif
        if (sched_setaffinity(tid, sizeof(g_saved_thread_affinity.mask),
                              &g_saved_thread_affinity.mask) != 0) {
            return false;
        }
        g_saved_thread_affinity.bind_depth = 0;
        CPU_ZERO(&g_saved_thread_affinity.mask);
        return true;
#else
        return false;
#endif
    }

    bool select_preferred_local_timer(
            const bool request_cpu0_affinity,
            LocalTimerSelection *out
    ) {
        if (out == nullptr) {
            return false;
        }

        *out = LocalTimerSelection{};

#if defined(__aarch64__)
        const bool affinity_attempted = request_cpu0_affinity;
        bool affinity_ok = false;
        if (affinity_attempted) {
            affinity_ok = bind_current_thread_to_cpu0();
            out->affinity_status = affinity_ok ? "bound_cpu0" : "bind_failed";
        }

        std::string failure_reason;
        if (arm64_cntvct_self_check(&failure_reason)) {
            out->kind = LocalTimerKind::Arm64Cntvct;
            out->source_label = "arm64_cntvct";
            return true;
        }

        out->fallback_reason = failure_reason;
        out->source_label = "clock_monotonic";
        return true;
#else
        out->source_label = "clock_monotonic";
        out->fallback_reason = "arm64 counter timer unavailable on this ABI";
        if (request_cpu0_affinity) {
            out->affinity_status = "unsupported_abi";
        }
        return true;
#endif
    }

}  // namespace ducktee::common
