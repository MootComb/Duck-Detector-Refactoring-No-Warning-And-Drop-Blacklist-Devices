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

#include "tee/trickystore/trickystore_probe.h"
#include "tee/trickystore/trickystore_internal.h"
#include <algorithm>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include "tee/common/local_timer.h"
#include "tee/common/syscall_facade.h"
#include "tee/common/timing_stats.h"

namespace ducktee::trickystore::detail {

    int raw_open(const char *path, int flags) {
#if defined(__NR_openat)
        return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, flags, 0));
#else
        return open(path, flags);
#endif
    }

    int open_binder_device() {
        int fd = raw_open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            fd = raw_open("/dev/vndbinder", O_RDWR | O_CLOEXEC);
        }
        return fd;
    }

    std::vector<ducktee::common::SyscallBackend> available_backends() {
        std::vector<ducktee::common::SyscallBackend> backends;
        for (const auto backend: kIoctlBackends) {
            if (ducktee::common::backend_available(backend)) {
                backends.push_back(backend);
            }
        }
        return backends;
    }

    std::vector<ducktee::common::SyscallBackend> rotated_available_backends(const int attempt) {
        auto backends = available_backends();
        if (backends.empty()) {
            return backends;
        }
        const auto rotation = static_cast<std::size_t>(attempt) % backends.size();
        std::rotate(backends.begin(), backends.begin() + rotation, backends.end());
        return backends;
    }

    ducktee::common::SyscallCallResult call_ioctl_backend(
            const ducktee::common::SyscallBackend backend,
            const int fd,
            const unsigned long request,
            void *arg
    ) {
        return ducktee::common::invoke_ioctl(backend, fd, request, arg);
    }

    void prepare_honeypot_payload(
            std::uint8_t *write_buffer,
            binder_write_read *bwr,
            std::uint8_t *fake_data
    ) {
        std::memset(write_buffer, 0, 256);
        const std::uint32_t command = BC_TRANSACTION;
        std::memcpy(write_buffer, &command, sizeof(command));

        binder_transaction_data transaction{};
        transaction.target.handle = 0;
        transaction.code = 1;
        transaction.data_size = 64;
        transaction.offsets_size = 0;

        std::memset(fake_data, 0, 64);
        const char *descriptor = "android.security.keystore2";
        std::memcpy(fake_data, descriptor, std::strlen(descriptor));
        transaction.data.ptr.buffer = reinterpret_cast<unsigned long>(fake_data);
        transaction.data.ptr.offsets = 0;

        std::memcpy(write_buffer + sizeof(command), &transaction, sizeof(transaction));

        std::memset(bwr, 0, sizeof(*bwr));
        bwr->write_buffer = reinterpret_cast<unsigned long>(write_buffer);
        bwr->write_size = sizeof(command) + sizeof(transaction);
    }

    bool collect_honeypot_backend_samples(
            const int binder_fd,
            const ducktee::common::LocalTimerSelection &timer,
            HoneypotTimingPath *path
    ) {
        if (path == nullptr ||
            !ducktee::common::backend_available(path->backend)) {
            return false;
        }

        std::uint8_t write_buffer[256];
        std::uint8_t fake_data[64];
        binder_write_read bwr{};
        prepare_honeypot_payload(write_buffer, &bwr, fake_data);

        for (int index = 0; index < kHoneypotIterations; ++index) {
            bwr.write_consumed = 0;
            std::uint64_t start = 0;
            std::uint64_t end = 0;
            if (!ducktee::common::local_timer_now_ns(timer, &start)) {
                path->failure = std::string("Failed to read ")
                                + timer.source_label
                                + " before ioctl.";
                return false;
            }
            const auto result = call_ioctl_backend(path->backend, binder_fd, BINDER_WRITE_READ,
                                                   &bwr);
            if (!result.available) {
                path->failure = std::string("Backend ")
                                + ducktee::common::backend_label(path->backend)
                                + " was unavailable for binder honeypot timing.";
                return false;
            }
            if (!ducktee::common::local_timer_now_ns(timer, &end)) {
                path->failure = std::string("Failed to read ")
                                + timer.source_label
                                + " after ioctl.";
                return false;
            }
            path->samples.push_back(end >= start ? (end - start) : 0);
        }

        path->stats = ducktee::common::summarize_samples(path->samples);
        path->available = path->stats.available;
        return path->available;
    }

    bool lower_paths_are_stable(const std::vector<HoneypotTimingPath> &paths) {
        std::vector<std::uint64_t> medians;
        for (const auto &path: paths) {
            if (path.backend == ducktee::common::SyscallBackend::Libc || !path.available) {
                continue;
            }
            medians.push_back(path.median_ns());
        }
        if (medians.size() < 2) {
            return true;
        }
        const auto minmax = std::minmax_element(medians.begin(), medians.end());
        const auto fastest = std::max<std::uint64_t>(1, *minmax.first);
        const auto slowest = *minmax.second;
        return slowest <= fastest + 25'000ULL && slowest <= fastest * 3ULL / 2ULL;
    }

    std::string describe_honeypot_path(const HoneypotTimingPath &path) {
        std::ostringstream builder;
        builder << ducktee::common::backend_label(path.backend) << "=";
        if (path.available) {
            builder << "med" << path.stats.median_ns << "ns";
            builder << "/mad" << path.stats.mad_ns << "ns";
            builder << "/p95" << path.stats.p95_ns << "ns";
        } else if (!path.failure.empty()) {
            builder << "unavailable(" << path.failure << ")";
        } else {
            builder << "unavailable";
        }
        return builder.str();
    }

    std::string describe_honeypot_paths(const std::vector<HoneypotTimingPath> &paths) {
        std::ostringstream builder;
        bool first = true;
        for (const auto &path: paths) {
            if (!first) {
                builder << ", ";
            }
            first = false;
            builder << describe_honeypot_path(path);
        }
        return builder.str();
    }

    HoneypotRunSummary analyze_honeypot_paths(const std::vector<HoneypotTimingPath> &paths) {
        HoneypotRunSummary summary;
        summary.path_summary = describe_honeypot_paths(paths);

        const auto libc_it = std::find_if(
                paths.begin(),
                paths.end(),
                [](const HoneypotTimingPath &path) {
                    return path.backend == ducktee::common::SyscallBackend::Libc;
                }
        );
        const HoneypotTimingPath *fastest_lower_path = nullptr;
        for (const auto &path: paths) {
            if (!path.available || path.backend == ducktee::common::SyscallBackend::Libc) {
                continue;
            }
            if (fastest_lower_path == nullptr || path.median_ns() < fastest_lower_path->median_ns()) {
                fastest_lower_path = &path;
            }
        }

        summary.stable_lower_paths = lower_paths_are_stable(paths);
        summary.libc_available = libc_it != paths.end() && libc_it->available;
        summary.lower_found = fastest_lower_path != nullptr;
        summary.libc_median_ns = summary.libc_available ? libc_it->median_ns() : 0;
        summary.fastest_lower_median_ns =
                summary.lower_found ? fastest_lower_path->median_ns() : 0;

        if (!summary.libc_available ||
            !summary.lower_found ||
            summary.libc_median_ns <= summary.fastest_lower_median_ns) {
            return summary;
        }

        summary.gap_ns = summary.libc_median_ns - summary.fastest_lower_median_ns;
        const std::uint64_t libc_mad = libc_it->stats.mad_ns;
        const std::uint64_t lower_mad = fastest_lower_path->stats.mad_ns;
        summary.noise_floor_ns = std::max({
                static_cast<std::uint64_t>(kHoneypotBaseGapThresholdNs),
                static_cast<std::uint64_t>(libc_mad * 4ULL),
                static_cast<std::uint64_t>(lower_mad * kHoneypotNoiseMultiplier),
        });
        summary.ratio_percent =
                (summary.libc_median_ns * 100ULL) / std::max<std::uint64_t>(1ULL,
                                                                            summary.fastest_lower_median_ns);
        summary.suspicious = summary.stable_lower_paths &&
                             summary.gap_ns > summary.noise_floor_ns &&
                             summary.ratio_percent >= kHoneypotRatioThresholdPercent;
        return summary;
    }

    MethodSnapshot run_single_ioctl_honeypot_probe(const int attempt) {
        MethodSnapshot snapshot;
        ScopedThreadAffinityRestore affinity_restore;
        ducktee::common::LocalTimerSelection timer;
        (void) ducktee::common::select_preferred_local_timer(true, &timer);
        affinity_restore.arm(timer.affinity_status == "bound_cpu0");
        snapshot.timer_source = timer.source_label;
        snapshot.timer_fallback_reason = timer.fallback_reason;
        snapshot.affinity_status = timer.affinity_status;

        const int binder_fd = open_binder_device();
        if (binder_fd < 0) {
            snapshot.detail = "Cannot open binder device for honeypot timing.";
            return snapshot;
        }

        void *mapped = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, binder_fd, 0);
        if (mapped == MAP_FAILED) {
            close(binder_fd);
            snapshot.detail = "Cannot mmap binder device for honeypot timing.";
            return snapshot;
        }

        std::vector<HoneypotTimingPath> paths;
        for (const auto backend: rotated_available_backends(attempt)) {
            HoneypotTimingPath path;
            path.backend = backend;
            (void) collect_honeypot_backend_samples(binder_fd, timer, &path);
            paths.push_back(std::move(path));
        }

        munmap(mapped, 4096);
        close(binder_fd);

        const HoneypotRunSummary run = analyze_honeypot_paths(paths);
        snapshot.honeypot_run_count = 1;
        snapshot.honeypot_suspicious_run_count = run.suspicious ? 1 : 0;
        snapshot.honeypot_median_gap_ns = run.gap_ns;
        snapshot.honeypot_median_noise_floor_ns = run.noise_floor_ns;
        snapshot.honeypot_median_ratio_percent = static_cast<int>(run.ratio_percent);

        if (run.suspicious) {
            snapshot.detected = true;
            std::ostringstream builder;
            builder
                    << "Keystore-style binder ioctl median timing diverged across redundant backends: "
                    << run.path_summary
                    << ". gap=" << run.gap_ns << "ns"
                    << ", noise_floor=" << run.noise_floor_ns << "ns"
                    << ", ratio=" << run.ratio_percent << "%"
                    << ". timer=" << snapshot.timer_source
                    << ", affinity=" << snapshot.affinity_status;
            if (!snapshot.timer_fallback_reason.empty()) {
                builder << ", fallback=" << snapshot.timer_fallback_reason;
            }
            builder << ".";
            snapshot.findings.push_back(builder.str());
            snapshot.detail = "Keystore-style binder honeypot found a libc-vs-lower-path timing anomaly.";
        } else {
            std::ostringstream builder;
            builder
                    << "Keystore-style binder honeypot timing stayed within normal bounds across redundant backends. "
                    << run.path_summary
                    << " gap=" << run.gap_ns << "ns"
                    << ", noise_floor=" << run.noise_floor_ns << "ns"
                    << ", ratio=" << run.ratio_percent << "%"
                    << " timer=" << snapshot.timer_source
                    << ", affinity=" << snapshot.affinity_status;
            if (!snapshot.timer_fallback_reason.empty()) {
                builder << ", fallback=" << snapshot.timer_fallback_reason;
            }
            builder << ".";
            if (!run.stable_lower_paths) {
                builder
                        << " Lower-level syscall and asm paths were not stable enough to escalate.";
            }
            snapshot.detail = builder.str();
        }
        return snapshot;
    }

    MethodSnapshot detect_ioctl_honeypot() {
        MethodSnapshot snapshot;
        int hit_count = 0;
        std::string last_detail;
        std::vector<std::uint64_t> gaps;
        std::vector<std::uint64_t> noise_floors;
        std::vector<std::uint64_t> ratios;

        for (int attempt = 0; attempt < kRepeatedProbeAttempts; ++attempt) {
            const MethodSnapshot single = run_single_ioctl_honeypot_probe(attempt);
            if (!single.detail.empty()) {
                last_detail = single.detail;
            }
            snapshot.timer_source = single.timer_source;
            snapshot.timer_fallback_reason = single.timer_fallback_reason;
            snapshot.affinity_status = single.affinity_status;
            if (single.honeypot_median_gap_ns > 0 ||
                single.honeypot_median_noise_floor_ns > 0 ||
                single.honeypot_median_ratio_percent > 0) {
                gaps.push_back(single.honeypot_median_gap_ns);
                noise_floors.push_back(single.honeypot_median_noise_floor_ns);
                ratios.push_back(static_cast<std::uint64_t>(single.honeypot_median_ratio_percent));
            }
            if (!single.detected) {
                continue;
            }
            ++hit_count;
            if (snapshot.findings.empty()) {
                snapshot.findings = single.findings;
            }
        }

        const auto gap_stats = ducktee::common::summarize_samples(gaps);
        const auto noise_stats = ducktee::common::summarize_samples(noise_floors);
        const auto ratio_stats = ducktee::common::summarize_samples(ratios);
        snapshot.honeypot_run_count = kRepeatedProbeAttempts;
        snapshot.honeypot_suspicious_run_count = hit_count;
        snapshot.honeypot_median_gap_ns = gap_stats.median_ns;
        snapshot.honeypot_gap_mad_ns = gap_stats.mad_ns;
        snapshot.honeypot_median_noise_floor_ns = noise_stats.median_ns;
        snapshot.honeypot_median_ratio_percent = static_cast<int>(ratio_stats.median_ns);
        snapshot.detected = hit_count >= 2;
        std::ostringstream builder;
        if (snapshot.detected) {
            builder << "Keystore-style binder honeypot triggered on " << hit_count
                    << "/" << kRepeatedProbeAttempts << " timing runs."
                    << " median_gap=" << snapshot.honeypot_median_gap_ns << "ns"
                    << ", gap_mad=" << snapshot.honeypot_gap_mad_ns << "ns"
                    << ", noise_floor=" << snapshot.honeypot_median_noise_floor_ns << "ns"
                    << ", median_ratio=" << snapshot.honeypot_median_ratio_percent << "%.";
            snapshot.detail = builder.str();
        } else {
            builder << "Keystore-style binder honeypot stayed within normal bounds across "
                    << kRepeatedProbeAttempts << " runs";
            if (hit_count > 0) {
                builder << " (" << hit_count << "/" << kRepeatedProbeAttempts
                        << " suspicious run).";
            } else {
                builder << ".";
            }
            if (gap_stats.available) {
                builder << " median_gap=" << snapshot.honeypot_median_gap_ns << "ns"
                        << ", gap_mad=" << snapshot.honeypot_gap_mad_ns << "ns"
                        << ", noise_floor=" << snapshot.honeypot_median_noise_floor_ns << "ns"
                        << ", median_ratio=" << snapshot.honeypot_median_ratio_percent << "%.";
            }
            if (!last_detail.empty()) {
                builder << " " << last_detail;
            }
            snapshot.detail = builder.str();
        }
        return snapshot;
    }

}  // namespace ducktee::trickystore::detail
