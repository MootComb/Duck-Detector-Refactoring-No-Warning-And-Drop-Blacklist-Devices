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

#include "nativeroot/probes/kernelpatch_latency_evidence.h"
#include "nativeroot/probes/kernelpatch_nr_supercall_latency_probe.h"

#include <cmath>
#include <cstdio>

namespace duckdetector::nativeroot {
    namespace {
        // Reference measurements only, not cross-device population bounds:
        // https://github.com/bmax121/KernelPatch/commit/84169d5d6be12e589ccac81d71dcebb80b22043a
        // pre-fix 4.281/0.460 = 9.31; fixed 0.943/0.607 = 1.55; stock 0.792/0.446 = 1.78.
        // The reported additional device measured 7.1569/3.6943 = 1.94. A ratio cancels
        // common multiplicative scaling, but not additive syscall overhead or differing
        // path-lookup costs. Until broader calibration exists, 3.0 is diagnostic only.
        constexpr double kElevatedRatio = 3.0;
    }

    ProbeResult classify_kernelpatch_latencies(double full_us, double empty_us, bool pinned) {
        ProbeResult result;
        result.checked_count = 1;
        if (!std::isfinite(full_us) || !std::isfinite(empty_us) ||
            full_us <= 0.0 || empty_us <= 0.0) {
            result.extra_text = "Unavailable: latency samples must be finite and positive.";
            return result;
        }

        const double ratio = full_us / empty_us;
        if (!std::isfinite(ratio) || ratio <= 0.0) {
            result.extra_text = "Unavailable: the latency ratio must be finite and positive.";
            return result;
        }

        result.aux_flags |= kLatencyAuxMeasured;
        char detail[384];
        snprintf(detail, sizeof(detail),
                 "Key path: %.4f us, empty key: %.4f us, diff: %.4f us, ratio: %.2f, same-core: %s. "
                 "Supporting timing evidence only; this ratio neither identifies nor excludes KernelPatch.",
                 full_us, empty_us, full_us - empty_us, ratio, pinned ? "yes" : "no");
        result.extra_text = detail;

        if (ratio > kElevatedRatio) {
            result.hit_count = 1;
            result.findings.push_back(Finding{
                    .group = "SIDE_CHANNEL",
                    .label = "Supercall key-length timing ratio",
                    .value = "Elevated ratio (supporting evidence)",
                    .detail = detail,
                    .severity = Severity::kWarning,
            });
        }
        return result;
    }

}  // namespace duckdetector::nativeroot
