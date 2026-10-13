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

#include <jni.h>

#include <exception>
#include <sstream>
#include <string>

#include "common/payload_codec.h"
#include "selinuxpolicy/selinux_status_abi_probe.h"

namespace {

    using duckdetector::selinux::StatusAbiOutcome;
    using duckdetector::selinux::StatusAbiProbeResult;
    using duckdetector::selinux::StatusAbiRequest;

    // The names SelinuxStatusAbiProbe parses; an outcome it does not know reads as inconclusive.
    const char *outcome_name(const StatusAbiOutcome outcome) {
        switch (outcome) {
            case StatusAbiOutcome::kViolation:
                return "VIOLATION";
            case StatusAbiOutcome::kNoViolation:
                return "NO_VIOLATION";
            case StatusAbiOutcome::kUnavailable:
                return "UNAVAILABLE";
            case StatusAbiOutcome::kInconclusive:
                return "INCONCLUSIVE";
        }
        return "INCONCLUSIVE";
    }

    const char *request_name(const StatusAbiRequest request) {
        switch (request) {
            case StatusAbiRequest::kTwoPageShared:
                return "TWO_PAGE_SHARED";
            case StatusAbiRequest::kOffsetShared:
                return "OFFSET_SHARED";
            case StatusAbiRequest::kWritablePrivate:
                return "WRITABLE_PRIVATE";
            case StatusAbiRequest::kMprotectWrite:
                return "MPROTECT_WRITE";
        }
        return "UNKNOWN";
    }

    std::string encode_result(const StatusAbiProbeResult &result) {
        std::ostringstream output;
        output << "ATTEMPTED=" << (result.attempted ? '1' : '0') << '\n';
        output << "OUTCOME=" << outcome_name(result.outcome) << '\n';
        if (result.outcome == StatusAbiOutcome::kViolation) {
            output << "VIOLATED=";
            bool first = true;
            for (int index = 0; index < duckdetector::selinux::kStatusAbiRequestCount; ++index) {
                if (!result.granted[index]) {
                    continue;
                }
                if (!first) {
                    output << ',';
                }
                first = false;
                output << request_name(static_cast<StatusAbiRequest>(index));
            }
            output << '\n';
        }
        if (result.page_size > 0) {
            output << "PAGE_SIZE=" << result.page_size << '\n';
        }
        if (!result.failure_reason.empty()) {
            output << "FAILURE_REASON="
                   << duckdetector::common::escape_payload_value(result.failure_reason) << '\n';
        }
        for (const std::string &note: result.notes) {
            output << "NOTE=" << duckdetector::common::escape_payload_value(note) << '\n';
        }
        return output.str();
    }

    std::string failure_payload(const std::string &reason) {
        return "ATTEMPTED=0\nOUTCOME=INCONCLUSIVE\nFAILURE_REASON=" +
               duckdetector::common::escape_payload_value(reason) + "\n";
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxStatusAbiProbe_nativeProbeStatusAbi(
        JNIEnv *env,
        jobject
) {
    std::string payload;
    try {
        payload = encode_result(duckdetector::selinux::probe_selinux_status_abi());
    } catch (const std::exception &error) {
        payload = failure_payload(std::string("Status ABI probe bridge failed: ") + error.what());
    } catch (...) {
        payload = failure_payload("Status ABI probe bridge failed with an unknown exception.");
    }
    return env->NewStringUTF(payload.c_str());
}
