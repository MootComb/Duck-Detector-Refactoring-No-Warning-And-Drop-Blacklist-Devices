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

#include "tee/trickystore/trickystore_internal.h"

#include "tee/common/syscall_facade.h"
#include "tee/common/timing_stats.h"

#include <algorithm>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace ducktee::trickystore::detail {

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

}  // namespace ducktee::trickystore::detail
