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
#include "tee/common/syscall_facade.h"
#include "tee/common/timing_stats.h"

namespace ducktee::trickystore {

    using namespace detail;

    ProbeSnapshot inspect_process() {
        ProbeSnapshot snapshot;
        std::vector<std::string> methods;
        std::vector<std::string> findings;

        std::vector<std::string> map_hits;
        if (maps_contain_trickystore(&map_hits)) {
            snapshot.detected = true;
            methods.push_back("MAPS_NAME_HIT");
            if (!map_hits.empty()) {
                findings.push_back("Suspicious process map entry: " + map_hits.front());
            }
        }

        const MethodSnapshot got_result = detect_got_ioctl_hook();
        if (got_result.detected) {
            snapshot.detected = true;
            snapshot.got_hook_detected = true;
            methods.push_back("GOT_HOOK");
            findings.insert(findings.end(), got_result.findings.begin(), got_result.findings.end());
        }

        const MethodSnapshot syscall_result = detect_syscall_ioctl_mismatch();
        if (syscall_result.detected) {
            snapshot.syscall_mismatch_detected = true;
            methods.push_back("SYSCALL_MISMATCH");
            findings.insert(findings.end(), syscall_result.findings.begin(),
                            syscall_result.findings.end());
        }

        const MethodSnapshot inline_result = detect_ioctl_inline_hook();
        if (inline_result.detected) {
            snapshot.detected = true;
            snapshot.inline_hook_detected = true;
            methods.push_back("INLINE_HOOK");
            findings.insert(findings.end(), inline_result.findings.begin(),
                            inline_result.findings.end());
        }

        const MethodSnapshot honeypot_result = detect_ioctl_honeypot();
        snapshot.timer_source = honeypot_result.timer_source;
        snapshot.timer_fallback_reason = honeypot_result.timer_fallback_reason;
        snapshot.affinity_status = honeypot_result.affinity_status;
        snapshot.honeypot_run_count = honeypot_result.honeypot_run_count;
        snapshot.honeypot_suspicious_run_count = honeypot_result.honeypot_suspicious_run_count;
        snapshot.honeypot_median_gap_ns = honeypot_result.honeypot_median_gap_ns;
        snapshot.honeypot_gap_mad_ns = honeypot_result.honeypot_gap_mad_ns;
        snapshot.honeypot_median_noise_floor_ns = honeypot_result.honeypot_median_noise_floor_ns;
        snapshot.honeypot_median_ratio_percent = honeypot_result.honeypot_median_ratio_percent;
        if (honeypot_result.detected) {
            snapshot.detected = true;
            snapshot.honeypot_detected = true;
            methods.push_back("HONEYPOT");
            findings.insert(findings.end(), honeypot_result.findings.begin(),
                            honeypot_result.findings.end());
        }

        snapshot.methods = methods;
        if (!findings.empty()) {
            std::ostringstream builder;
            builder << "methods=";
            for (std::size_t index = 0; index < methods.size(); ++index) {
                if (index > 0) {
                    builder << ",";
                }
                builder << methods[index];
            }
            builder << " | " << findings.front();
            snapshot.details = builder.str();
        } else if (snapshot.syscall_mismatch_detected) {
            snapshot.details = syscall_result.detail;
        } else {
            std::ostringstream builder;
            builder << got_result.detail
                    << " | " << inline_result.detail
                    << " | " << honeypot_result.detail;
            snapshot.details = builder.str();
        }
        return snapshot;
    }

}  // namespace ducktee::trickystore
