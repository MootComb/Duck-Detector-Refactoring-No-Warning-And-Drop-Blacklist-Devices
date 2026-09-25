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

#include "virtualization/honeypot_traps.h"
#include "virtualization/honeypot_traps_internal.h"
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

    std::string encode_value(const std::string &value) {
        return common::escape_payload_value(value);
    }

    long long monotonic_ns() {
        struct timespec now{};
        clock_gettime(CLOCK_MONOTONIC, &now);
        return static_cast<long long>(now.tv_sec) * 1000000000LL + now.tv_nsec;
    }

    /**
     * Relative spread of the samples, or nothing when no spread can be expressed.
     *
     * The empty result is not the same as a coefficient of zero and callers must not
     * collapse the two. A zero mean means the samples carry no elapsed time at all, so
     * there is nothing to take a ratio against; reporting 0.0 for that case would hand
     * back the most uniform value the scale has for a measurement that never happened.
     */
    std::optional<double> coefficient_of_variation(const std::vector<long long> &samples) {
        if (samples.empty()) {
            return std::nullopt;
        }
        const double mean = std::accumulate(samples.begin(), samples.end(), 0.0) /
                            static_cast<double>(samples.size());
        if (mean <= 0.0) {
            return std::nullopt;
        }
        double variance = 0.0;
        for (const auto sample: samples) {
            const double delta = static_cast<double>(sample) - mean;
            variance += delta * delta;
        }
        variance /= static_cast<double>(samples.size());
        return sqrt(variance) / mean;
    }

    TrapResult make_base_result(bool supported) {
        TrapResult result;
        result.available = true;
        result.supported = supported;
        return result;
    }

    TrapResult finalize_result(TrapResult result, const std::string &prefix) {
        std::ostringstream detail;
        detail << prefix;
        for (std::size_t index = 0; index < result.attempts.size(); ++index) {
            detail << "\nAttempt " << (index + 1) << ": " << result.attempts[index].detail;
        }
        result.detail = detail.str();
        return result;
    }

    // Only reached from the non-arm64 fallbacks, so the arm64-v8a build compiles no call to it.
    [[maybe_unused]] TrapResult build_unsupported_result(const std::string &detail) {
        TrapResult result;
        result.available = true;
        result.supported = false;
        result.detail = detail;
        return result;
    }

    std::string encode_basic_pack(
            bool available,
            bool supported,
            bool disabled,
            const std::string &detail
    ) {
        std::ostringstream output;
        output << "AVAILABLE=" << (available ? 1 : 0) << '\n';
        output << "SUPPORTED=" << (supported ? 1 : 0) << '\n';
        output << "DISABLED=" << (disabled ? 1 : 0) << '\n';
        output << "DETAIL=" << encode_value(detail) << '\n';
        return output.str();
    }

    // Used only from run_syscall_item, whose instantiations sit behind arm64-only guards.
    [[maybe_unused]] bool unsupported_syscall_errno(int err) {
        return err == ENOSYS || err == EINVAL;
    }

}  // namespace duckdetector::virtualization::detail


namespace duckdetector::virtualization {

    using namespace detail;

    /**
     * Looks for sched_yield timings that repeat more evenly than real scheduling tends to.
     *
     * The bounds below are empirical, and sched_yield gives no specification to anchor them
     * to. Its man page puts the call's behaviour under SCHED_OTHER, which is what an Android
     * app thread runs, explicitly outside what is specified: "Use of sched_yield() with
     * nondeterministic scheduling policies such as SCHED_OTHER is unspecified".
     *
     * That same page also names the main false positive. "If the calling thread is the only
     * thread in the highest priority list at that time, it will continue to run after a call
     * to sched_yield()", so on an idle device no context switch happens and what is left to
     * measure is a bare syscall round trip, which repeats closely by nature. Evenness here is
     * therefore not by itself evidence of an emulated scheduler, which is why the bounds are
     * set tight enough that ordinary vDSO clock jitter clears them, and why two of three
     * attempts must agree before the consumer treats this as a signal at all.
     */
    TrapResult run_timing_trap() {
        // Tight enough that the jitter of the two clock reads around sched_yield normally
        // exceeds it on its own. Loosening it would start flagging idle devices.
        constexpr double kUniformityCeiling = 0.03;

        // Guards against reading a descheduled sample window as a tidy one. A yield costing
        // this long means the thread lost the CPU, so uniformity says nothing about the
        // scheduler's own behaviour.
        constexpr long long kMeanCeilingNs = 250000LL;

        // Microsecond granularity, so sub-microsecond yields all land in one bucket and this
        // does little work beyond rejecting obviously spread-out sample sets.
        constexpr std::size_t kBucketCeiling = 2;

        TrapResult result = make_base_result(true);
        for (int attempt = 0; attempt < 3; ++attempt) {
            std::vector<long long> samples;
            samples.reserve(32);
            for (int sample = 0; sample < 32; ++sample) {
                const long long start = monotonic_ns();
                sched_yield();
                const long long end = monotonic_ns();
                samples.push_back(end - start);
            }
            std::set<long long> buckets;
            for (const auto sample: samples) {
                buckets.insert(sample / 1000LL);
            }
            const std::optional<double> cv = coefficient_of_variation(samples);
            const long long mean = std::accumulate(samples.begin(), samples.end(), 0LL) /
                                   static_cast<long long>(samples.size());

            // Every sample reading as no elapsed time leaves no spread to judge, which
            // happens where the clock is too coarse to resolve a yield. Counting the attempt
            // would turn a measurement that did not happen into the most uniform result the
            // scale can express, so it stays out of the completed tally and the consumer's
            // two-attempt minimum keeps it off both verdicts.
            if (!cv.has_value()) {
                result.attempts.push_back(
                        TrapAttempt{false,
                                    "mean=0ns (no elapsed time resolved, uniformity "
                                    "unavailable)"}
                );
                continue;
            }

            const bool suspicious = buckets.size() <= kBucketCeiling &&
                                    *cv < kUniformityCeiling &&
                                    mean < kMeanCeilingNs;
            result.completedAttempts += 1;
            if (suspicious) {
                result.suspiciousAttempts += 1;
            }
            std::ostringstream detail;
            detail << "mean=" << mean << "ns cv=" << *cv
                   << " unique_us_buckets=" << buckets.size();
            result.attempts.push_back(TrapAttempt{suspicious, detail.str()});
        }
        return finalize_result(
                result,
                "Measures sched_yield timing evenness across three native attempts. "
                "sched_yield is unspecified under SCHED_OTHER and returns without switching "
                "when nothing else is runnable, so evenness alone is weak evidence."
        );
    }

    TrapResult run_syscall_parity_trap() {
        TrapResult result = make_base_result(true);
        const pid_t pid = getpid();
        for (int attempt = 0; attempt < 3; ++attempt) {
            std::ostringstream path;
            path << "/proc/self/definitely_missing_virtualization_" << pid << "_" << attempt;

            // Unlike the sacrificial pack, these two names are accurate: open() is a real
            // bionic entry point, and the second call goes straight to openat through
            // syscall(), so a hook on the former is observable against the latter.
            errno = 0;
            const long long libcStart = monotonic_ns();
            const int libcRet = open(path.str().c_str(), O_RDONLY | O_CLOEXEC);
            const int libcErrno = errno;
            if (libcRet >= 0) {
                close(libcRet);
            }
            const long long libcElapsed = monotonic_ns() - libcStart;

            errno = 0;
            const long long rawStart = monotonic_ns();
            const long rawRet = syscall(__NR_openat, AT_FDCWD, path.str().c_str(),
                                        O_RDONLY | O_CLOEXEC, 0);
            const int rawErrno = errno;
            if (rawRet >= 0) {
                close(static_cast<int>(rawRet));
            }
            const long long rawElapsed = monotonic_ns() - rawStart;

            const bool suspicious = libcRet != rawRet || libcErrno != rawErrno;
            result.completedAttempts += 1;
            if (suspicious) {
                result.suspiciousAttempts += 1;
            }

            std::ostringstream detail;
            detail << "libc_ret=" << libcRet << " libc_errno=" << libcErrno
                   << " raw_ret=" << rawRet << " raw_errno=" << rawErrno
                   << " libc_ns=" << libcElapsed << " raw_ns=" << rawElapsed;
            result.attempts.push_back(TrapAttempt{suspicious, detail.str()});
        }
        return finalize_result(result,
                               "Compares libc and raw openat error paths for a transient missing-path trap.");
    }

    /**
     * Checks the firmware-provided counter frequency against the rate the kernel's own
     * timekeeping runs at.
     *
     * This is not a comparison of two independent clocks, and must not be read as one. On
     * arm64 CLOCK_MONOTONIC comes from the same register this probe reads: the vDSO's
     * __arch_get_hw_counter (arch/arm64/include/asm/vdso/gettimeofday.h) issues
     * "isb; mrs cntvct_el0", or CNTVCTSS_EL0 where FEAT_ECV is present. Both sides of the
     * comparison therefore observe one counter, and what differs is the scaling: this probe
     * divides by CNTFRQ_EL0, while CLOCK_MONOTONIC applies the mult/shift the kernel derived
     * from the arch timer rate it established at boot.
     *
     * That makes the check worth running even so, because CNTFRQ_EL0 is not authoritative
     * about the hardware. Arm ARM D12.1.2 has it UNKNOWN at reset and written by firmware at
     * the highest exception level; nothing in hardware validates it. An environment that
     * advertises a frequency the counter does not actually tick at will disagree with the
     * kernel's calibrated rate, which is the divergence being looked for.
     */
    TrapResult run_asm_counter_trap() {
#if defined(__aarch64__)
        // CNTFRQ_EL0 carries the frequency in its ClockFreq field, bits [31:0]. Masking
        // bounds a firmware-written value before it is used as a divisor, so that upper bits
        // cannot pass the zero check below and then divide the counter delta down to nothing.
        constexpr unsigned long long kClockFreqMask = 0xffff'ffffULL;

        // Deliberately coarse: both sides read one counter, so they agree to within
        // clocksource rounding plus the two extra register reads inside the wall-clock
        // window. Only a gross mismatch, such as an advertised frequency several times off
        // the real tick rate, clears this. The cost of that margin is a false negative for
        // subtle timer scaling, which this trap cannot see.
        constexpr long long kGrossMismatchNumerator = 3LL;
        constexpr long long kGrossMismatchDenominator = 4LL;

        TrapResult result = make_base_result(true);
        for (int attempt = 0; attempt < 3; ++attempt) {
            const unsigned long long freq =
                    virtualization_arm64_read_cntfrq() & kClockFreqMask;
            const long long wallStart = monotonic_ns();
            const unsigned long long counterStart = virtualization_arm64_read_cntvct();
            for (int i = 0; i < 256; ++i) {
                syscall(__NR_getpid);
            }
            const unsigned long long counterEnd = virtualization_arm64_read_cntvct();
            const long long wallEnd = monotonic_ns();

            // A frequency of zero means firmware never programmed the register, so there is
            // no divisor and no measurement. Leaving the attempt uncounted keeps that apart
            // from a completed comparison that disagreed: the consumer needs two completed
            // attempts before it will call this either suspicious or clean, so an
            // unprogrammed register lands on neither instead of being reported as evidence.
            if (freq == 0ULL) {
                result.attempts.push_back(
                        TrapAttempt{false,
                                    "freq=0 (cntfrq_el0 unprogrammed, comparison unavailable)"}
                );
                continue;
            }

            // Zero covers both a counter that did not advance and one that went backwards.
            // Either is anomalous on its own: at the frequencies the architecture allows,
            // 256 syscalls always span several ticks.
            const unsigned long long counterDelta = counterEnd > counterStart
                                                    ? (counterEnd - counterStart)
                                                    : 0ULL;
            const long long wallDelta = wallEnd - wallStart;

            // Whole seconds are converted apart from the remainder so that counterDelta
            // never multiplies into an overflow. A straight counterDelta * 1e9 wraps once the
            // delta passes ~1.8e10 ticks, which is only ~18 seconds of counter at the 1GHz
            // fixed frequency Armv8.6 mandates, and this window can stretch that far if the
            // process is descheduled mid-loop. The remainder stays below freq, itself bounded
            // to 32 bits above, so its multiplication is in range.
            const unsigned long long deltaSeconds = counterDelta / freq;
            const unsigned long long deltaRemainder = counterDelta % freq;
            const long long counterNs = static_cast<long long>(
                    deltaSeconds * 1000000000ULL + (deltaRemainder * 1000000000ULL) / freq
            );
            const long long diff = llabs(counterNs - wallDelta);
            const bool suspicious = counterDelta == 0ULL ||
                                    (wallDelta > 0LL &&
                                     diff > (wallDelta * kGrossMismatchNumerator /
                                             kGrossMismatchDenominator));

            result.completedAttempts += 1;
            if (suspicious) {
                result.suspiciousAttempts += 1;
            }

            std::ostringstream detail;
            detail << "freq=" << freq << " counter_delta=" << counterDelta
                   << " counter_ns=" << counterNs << " wall_ns=" << wallDelta;
            result.attempts.push_back(TrapAttempt{suspicious, detail.str()});
        }
        return finalize_result(
                result,
                "Checks the firmware cntfrq_el0 value against the rate the kernel's own "
                "timekeeping uses. Both sides read cntvct_el0, so this is one counter scaled "
                "two ways, not two independent clocks."
        );
#else
        return build_unsupported_result("ASM counter trap is only supported on arm64-v8a.");
#endif
    }

    TrapResult run_asm_raw_syscall_trap() {
#if defined(__aarch64__)
        TrapResult result = make_base_result(true);
        for (int attempt = 0; attempt < 3; ++attempt) {
            const pid_t libcPid = getpid();
            const long rawPid = virtualization_arm64_getpid_syscall();
            const bool suspicious = rawPid <= 0 || static_cast<pid_t>(rawPid) != libcPid;
            result.completedAttempts += 1;
            if (suspicious) {
                result.suspiciousAttempts += 1;
            }
            std::ostringstream detail;
            detail << "libc_getpid=" << libcPid << " asm_getpid=" << rawPid;
            result.attempts.push_back(TrapAttempt{suspicious, detail.str()});
        }
        return finalize_result(result, "Compares libc getpid against an arm64 raw-svc syscall path.");
#else
        return build_unsupported_result("ASM raw syscall trap is only supported on arm64-v8a.");
#endif
    }

    std::string encode_trap(const TrapResult &result) {
        std::ostringstream output;
        output << "AVAILABLE=" << (result.available ? 1 : 0) << '\n';
        output << "SUPPORTED=" << (result.supported ? 1 : 0) << '\n';
        output << "COMPLETED_ATTEMPTS=" << result.completedAttempts << '\n';
        output << "SUSPICIOUS_ATTEMPTS=" << result.suspiciousAttempts << '\n';
        output << "DETAIL=" << encode_value(result.detail) << '\n';
        for (const auto &attempt: result.attempts) {
            output << "ATTEMPT=" << (attempt.suspicious ? 1 : 0) << '\t'
                   << encode_value(attempt.detail) << '\n';
        }
        return output.str();
    }

}  // namespace duckdetector::virtualization
