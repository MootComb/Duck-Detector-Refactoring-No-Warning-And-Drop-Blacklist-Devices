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

#include <unistd.h>

#include <cstddef>
#include <sstream>
#include <string>
#include <vector>

namespace ducktee::trickystore::detail {

    std::string format_backend_observation(const IoctlBackendObservation &observation) {
        std::ostringstream builder;
        builder << ducktee::common::backend_label(observation.backend)
                << "(ret=" << observation.result
                << ", errno=" << observation.error_number
                << ", version=" << observation.protocol_version << ")";
        return builder.str();
    }

    bool backend_samples_aligned(
            const IoctlBackendObservation &reference,
            const IoctlBackendObservation &candidate
    ) {
        return reference.result == candidate.result &&
               reference.error_number == candidate.error_number &&
               reference.protocol_version == candidate.protocol_version;
    }

    MethodSnapshot run_single_syscall_ioctl_mismatch_probe() {
        MethodSnapshot snapshot;
        const int binder_fd = open_binder_device();
        if (binder_fd < 0) {
            snapshot.detail = "Cannot open binder device for ioctl backend comparison.";
            return snapshot;
        }

        std::vector<IoctlBackendObservation> observations;
        for (const auto backend: available_backends()) {
            binder_version version{};
            const auto result = call_ioctl_backend(backend, binder_fd, BINDER_VERSION,
                                                   &version);
            if (!result.available) {
                continue;
            }
            observations.push_back(IoctlBackendObservation{
                    .backend = backend,
                    .result = result.value,
                    .error_number = result.error_number,
                    .protocol_version = static_cast<int>(version.protocol_version),
            });
        }
        close(binder_fd);

        if (observations.size() < 2) {
            snapshot.detail = "Fewer than two ioctl backends were available for binder comparison.";
            return snapshot;
        }

        const auto &reference = observations.front();
        for (std::size_t index = 1; index < observations.size(); ++index) {
            if (backend_samples_aligned(reference, observations[index])) {
                continue;
            }
            snapshot.detected = true;
            std::ostringstream builder;
            builder << "Binder version query diverged across backends: "
                    << format_backend_observation(reference) << " vs "
                    << format_backend_observation(observations[index]) << ".";
            snapshot.findings.push_back(builder.str());
            snapshot.detail = "Binder version query returned different results across libc/syscall/asm backends.";
            return snapshot;
        }

        std::ostringstream builder;
        builder << "Binder version query aligned across ";
        for (std::size_t index = 0; index < observations.size(); ++index) {
            if (index > 0) {
                builder << ", ";
            }
            builder << ducktee::common::backend_label(observations[index].backend);
        }
        builder << " backends.";
        snapshot.detail = builder.str();
        return snapshot;
    }

    MethodSnapshot detect_syscall_ioctl_mismatch() {
        MethodSnapshot snapshot;
        int hit_count = 0;
        std::string last_detail;

        for (int attempt = 0; attempt < kRepeatedProbeAttempts; ++attempt) {
            const MethodSnapshot single = run_single_syscall_ioctl_mismatch_probe();
            if (!single.detail.empty()) {
                last_detail = single.detail;
            }
            if (!single.detected) {
                continue;
            }
            ++hit_count;
            if (snapshot.findings.empty()) {
                snapshot.findings = single.findings;
            }
        }

        snapshot.detected = hit_count >= 2;
        std::ostringstream builder;
        if (snapshot.detected) {
            builder << "Binder version ioctl diverged on " << hit_count
                    << "/" << kRepeatedProbeAttempts << " backend-comparison probes.";
            snapshot.detail = builder.str();
        } else {
            builder << "Binder version ioctl stayed aligned across "
                    << kRepeatedProbeAttempts << " backend-comparison probes";
            if (hit_count > 0) {
                builder << " (" << hit_count << "/" << kRepeatedProbeAttempts
                        << " suspicious run).";
            } else {
                builder << ".";
            }
            if (!last_detail.empty()) {
                builder << " " << last_detail;
            }
            snapshot.detail = builder.str();
        }
        return snapshot;
    }

}  // namespace ducktee::trickystore::detail
