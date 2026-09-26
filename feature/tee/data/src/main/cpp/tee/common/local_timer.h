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

#ifndef DUCKDETECTOR_TEE_COMMON_LOCAL_TIMER_H
#define DUCKDETECTOR_TEE_COMMON_LOCAL_TIMER_H

#include <cstdint>
#include <string>

// Local timers for native timing probes. The reads, local_timer_now_ns and register_timer_time_ns,
// are defined in syscall_facade.cpp beside the syscall paths they time, so the counter and clock
// reads can be inlined into them; selecting a timer and pinning the thread happen before any
// measurement and are defined in local_timer_setup.cpp.
namespace ducktee::common {

    enum class LocalTimerKind {
        Monotonic,
        Arm64Cntvct,
    };

    struct LocalTimerSelection {
        LocalTimerKind kind = LocalTimerKind::Monotonic;
        std::string source_label = "clock_monotonic";
        std::string fallback_reason;
        std::string affinity_status = "not_requested";
    };

    bool register_timer_time_ns(std::uint64_t *out_ns);

    bool bind_current_thread_to_cpu0();

    bool restore_current_thread_affinity();

    bool select_preferred_local_timer(
            bool request_cpu0_affinity,
            LocalTimerSelection *out
    );

    bool local_timer_now_ns(const LocalTimerSelection &timer, std::uint64_t *out_ns);

}  // namespace ducktee::common

#endif  // DUCKDETECTOR_TEE_COMMON_LOCAL_TIMER_H
