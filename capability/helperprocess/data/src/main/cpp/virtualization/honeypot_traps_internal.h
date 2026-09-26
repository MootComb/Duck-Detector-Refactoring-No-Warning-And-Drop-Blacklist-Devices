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

#pragma once

#include "virtualization/honeypot_traps.h"
#include "common/payload_codec.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <math.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <algorithm>
#include <cstdint>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace duckdetector::virtualization::detail {

    std::string encode_value(const std::string &value);

    long long monotonic_ns();

    std::optional<double> coefficient_of_variation(const std::vector<long long> &samples);

    TrapResult make_base_result(bool supported);

    TrapResult finalize_result(TrapResult result, const std::string &prefix);

    [[maybe_unused]] TrapResult build_unsupported_result(const std::string &detail);

    // Read and set only from arm64-only code paths, so other ABIs compile no reference to it.
    [[maybe_unused]] inline bool g_sacrificialSyscallPackDisabled = false;

    std::string encode_basic_pack(
            bool available,
            bool supported,
            bool disabled,
            const std::string &detail
    );

    [[maybe_unused]] bool unsupported_syscall_errno(int err);

#if defined(__aarch64__)
    extern "C" unsigned long long virtualization_arm64_read_cntvct();
    extern "C" unsigned long long virtualization_arm64_read_cntfrq();
    extern "C" long virtualization_arm64_getpid_syscall();

    inline long asm_syscall6(
            long number,
            long arg0,
            long arg1,
            long arg2,
            long arg3,
            long arg4,
            long arg5,
            int *outErrno
    ) {
        register long x0 __asm__("x0") = arg0;
        register long x1 __asm__("x1") = arg1;
        register long x2 __asm__("x2") = arg2;
        register long x3 __asm__("x3") = arg3;
        register long x4 __asm__("x4") = arg4;
        register long x5 __asm__("x5") = arg5;
        register long x8 __asm__("x8") = number;
        __asm__ volatile("svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
        : "memory");
        if (x0 < 0) {
            if (outErrno != nullptr) {
                *outErrno = static_cast<int>(-x0);
            }
            return -1;
        }
        if (outErrno != nullptr) {
            *outErrno = 0;
        }
        return x0;
    }

    /**
     * One syscall issued three times: twice through bionic's syscall() wrapper and once
     * through an inline svc.
     *
     * Only two mechanisms are present here, not three. The wrapper pair is deliberately
     * the same path twice, because that is what gives this attempt a noise floor to judge
     * the inline result against. Naming the second call "raw", as this struct once did,
     * implied a second independent layer and invited a comparison between a path and
     * itself.
     *
     * The comparison that carries meaning is wrapper against inline: userspace
     * interposition can reach the wrapper's PLT entry or its prologue, while an svc
     * compiled into this translation unit has no symbol to hook.
     */
    struct SyscallAttemptTriplet {
        long wrapperRet = -1;
        int wrapperErrno = 0;
        long wrapperRepeatRet = -1;
        int wrapperRepeatErrno = 0;
        long asmRet = -1;
        int asmErrno = 0;
        long long wrapperElapsedNs = 0;
        long long wrapperRepeatElapsedNs = 0;
        long long asmElapsedNs = 0;
    };

    // Applied to the gap between the inline call and the wrapper baseline, not to a raw
    // duration, so both keep their original role of admitting only a gross outlier.
    constexpr long long kTimingGapFactor = 4LL;
    constexpr long long kTimingGapFloorNs = 50000LL;

    /**
     * Whether two attempts at the same syscall agree on what happened.
     *
     * Return values are compared only for the failure case, where errno carries the
     * outcome. On success the number itself is not comparable: memfd_create and pidfd_open
     * hand back a freshly allocated descriptor, and which number the kernel picks depends
     * on what is free in the table at that moment. Requiring equality there would read an
     * ordinary descriptor-numbering difference as one layer disagreeing with another.
     */
    inline bool outcomes_agree(long firstRet, int firstErrno, long secondRet, int secondErrno) {
        const bool firstFailed = firstRet < 0;
        if (firstFailed != (secondRet < 0)) {
            return false;
        }
        return !firstFailed || firstErrno == secondErrno;
    }

    struct SyscallItemAccumulator {
        std::string label;
        int completedAttempts = 0;
        int suspiciousAttempts = 0;
        std::vector<TrapAttempt> attempts;
    };

    template <typename Callable>
    bool run_syscall_item(
            const std::string &label,
            Callable callable,
            SyscallItemAccumulator *accumulator
    ) {
        accumulator->label = label;
        for (int attempt = 0; attempt < 3; ++attempt) {
            SyscallAttemptTriplet triplet = callable(attempt);
            if (unsupported_syscall_errno(triplet.wrapperErrno) ||
                unsupported_syscall_errno(triplet.wrapperRepeatErrno) ||
                unsupported_syscall_errno(triplet.asmErrno)) {
                return false;
            }

            // The wrapper pair is one path called twice, so a disagreement between them is
            // the call behaving non-reproducibly rather than a layer diverging. Without a
            // stable baseline there is nothing for the inline result to be compared
            // against, so the attempt records why and stays out of the completed tally.
            if (!outcomes_agree(triplet.wrapperRet, triplet.wrapperErrno,
                                triplet.wrapperRepeatRet, triplet.wrapperRepeatErrno)) {
                std::ostringstream unstable;
                unstable << "wrapper pair disagreed (ret " << triplet.wrapperRet << "/"
                         << triplet.wrapperRepeatRet << ", errno " << triplet.wrapperErrno
                         << "/" << triplet.wrapperRepeatErrno
                         << "), no stable baseline to compare the inline svc against";
                accumulator->attempts.push_back(TrapAttempt{false, unstable.str()});
                continue;
            }

            const bool returnMismatch = !outcomes_agree(
                    triplet.wrapperRet, triplet.wrapperErrno,
                    triplet.asmRet, triplet.asmErrno
            );

            // Scaled against the wrapper pair's own gap rather than against the fastest of
            // the three. Those two calls take the same path, so whatever separates them is
            // this attempt's noise, mostly preemption; measuring the inline call against
            // the smallest raw sample instead let that noise alone clear the bar. The
            // factor and floor are the ones this trap already used, kept because they are
            // coarse on purpose: a syscall runs in single-digit microseconds, so the floor
            // means only a stall far outside that range counts.
            const long long controlGapNs = std::max(1LL, llabs(
                    triplet.wrapperElapsedNs - triplet.wrapperRepeatElapsedNs
            ));
            const long long wrapperFloorNs = std::min(
                    triplet.wrapperElapsedNs, triplet.wrapperRepeatElapsedNs
            );
            const long long asmGapNs = llabs(triplet.asmElapsedNs - wrapperFloorNs);
            const bool timingMismatch = asmGapNs > controlGapNs * kTimingGapFactor &&
                                        asmGapNs > kTimingGapFloorNs;

            const bool suspicious = returnMismatch || timingMismatch;
            accumulator->completedAttempts += 1;
            if (suspicious) {
                accumulator->suspiciousAttempts += 1;
            }

            std::ostringstream detail;
            detail << "wrapper_ret=" << triplet.wrapperRet
                   << " wrapper_errno=" << triplet.wrapperErrno
                   << " wrapper_repeat_ret=" << triplet.wrapperRepeatRet
                   << " wrapper_repeat_errno=" << triplet.wrapperRepeatErrno
                   << " asm_ret=" << triplet.asmRet << " asm_errno=" << triplet.asmErrno
                   << " wrapper_ns=" << triplet.wrapperElapsedNs
                   << " wrapper_repeat_ns=" << triplet.wrapperRepeatElapsedNs
                   << " asm_ns=" << triplet.asmElapsedNs
                   << " control_gap_ns=" << controlGapNs
                   << " asm_gap_ns=" << asmGapNs;
            accumulator->attempts.push_back(TrapAttempt{suspicious, detail.str()});
        }
        return true;
    }

    inline std::string encode_sacrificial_item(const SyscallItemAccumulator &item) {
        std::ostringstream output;
        output << "ITEM=" << item.label << '\t' << 1 << '\t'
               << item.completedAttempts << '\t'
               << item.suspiciousAttempts << '\t'
               << encode_value(item.attempts.empty() ? "" : item.attempts.front().detail) << '\n';
        for (const auto &attempt: item.attempts) {
            output << "ATTEMPT=" << item.label << '\t'
                   << (attempt.suspicious ? 1 : 0)
                   << '\t' << encode_value(attempt.detail) << '\n';
        }
        return output.str();
    }
#endif

}  // namespace duckdetector::virtualization::detail
