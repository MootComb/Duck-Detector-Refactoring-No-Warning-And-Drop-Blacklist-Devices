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

#include <cassert>
#include <cmath>
#include <limits>
#include <utility>

using namespace duckdetector::nativeroot;

static void no_family_attribution(const ProbeResult &result) {
    assert(!result.flags.root && !result.flags.apatch && !result.flags.kernel_su &&
           !result.flags.magisk && !result.flags.susfs);
}

static void valid_sample(double full, double empty, bool elevated) {
    const auto result = classify_kernelpatch_latencies(full, empty, true);
    assert(result.checked_count == 1);
    assert((result.aux_flags & kLatencyAuxMeasured) != 0);
    no_family_attribution(result);
    assert(result.hit_count == (elevated ? 1 : 0));
    assert(result.findings.size() == (elevated ? 1U : 0U));
    assert(result.extra_text.find("ratio:") != std::string::npos);
    assert(result.extra_text.find("neither identifies nor excludes") != std::string::npos);
    if (elevated) {
        assert(result.findings.front().severity == Severity::kWarning);
        assert(result.findings.front().group == "SIDE_CHANNEL");
    }
}

int main() {
    // Upstream reference averages and the additional reported negative sample.
    valid_sample(4.281, 0.460, true);
    valid_sample(0.943, 0.607, false);
    valid_sample(0.792, 0.446, false);
    valid_sample(7.1569, 3.6943, false);
    // Common additive overhead can hide the pre-fix reference ratio; it must
    // never yield a root-family conclusion, whether above or below threshold.
    valid_sample(6.281, 2.460, false);
    valid_sample(42.81, 4.60, true);
    valid_sample(3.0, 1.0, false);
    valid_sample(std::nextafter(3.0, 4.0), 1.0, true);
    valid_sample(std::nextafter(3.0, 2.0), 1.0, false);

    const double nan = std::numeric_limits<double>::quiet_NaN();
    const double inf = std::numeric_limits<double>::infinity();
    const double smallest = std::numeric_limits<double>::min();
    const double largest = std::numeric_limits<double>::max();
    const std::pair<double, double> invalid[] = {
            {1.0, 0.0}, {0.0, 1.0}, {1.0, -1.0}, {-1.0, 1.0},
            {nan, 1.0}, {1.0, nan}, {inf, 1.0}, {1.0, inf},
            {largest, smallest}, {smallest, largest},
    };
    for (const auto &sample : invalid) {
        const auto result = classify_kernelpatch_latencies(sample.first, sample.second, true);
        assert((result.aux_flags & kLatencyAuxMeasured) == 0);
        assert(result.hit_count == 0 && result.findings.empty());
        assert(result.extra_text.find("Unavailable:") == 0);
        no_family_attribution(result);
    }

    const auto unpinned = classify_kernelpatch_latencies(4.281, 0.460, false);
    assert(unpinned.extra_text.find("same-core: no") != std::string::npos);
    no_family_attribution(unpinned);
    assert(unpinned.findings.front().severity == Severity::kWarning);
}
