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
#include "selinuxpolicy/selinux_status_page_probe.h"

namespace {

    using duckdetector::selinux::StatusPageHeader;
    using duckdetector::selinux::StatusPageOutcome;
    using duckdetector::selinux::StatusPageProbeResult;

    // The names SelinuxStatusPageProbe parses; an outcome it does not know reads as inconclusive.
    const char *outcome_name(const StatusPageOutcome outcome) {
        switch (outcome) {
            case StatusPageOutcome::kIntact:
                return "INTACT";
            case StatusPageOutcome::kFaulted:
                return "FAULTED";
            case StatusPageOutcome::kUnavailable:
                return "UNAVAILABLE";
            case StatusPageOutcome::kInconclusive:
                return "INCONCLUSIVE";
        }
        return "INCONCLUSIVE";
    }

    std::string encode_result(const StatusPageProbeResult &result) {
        std::ostringstream output;
        output << "ATTEMPTED=" << (result.attempted ? '1' : '0') << '\n';
        output << "OUTCOME=" << outcome_name(result.outcome) << '\n';
        if (result.terminating_signal != 0) {
            output << "SIGNAL=" << result.terminating_signal << '\n';
        }
        if (result.header.has_value()) {
            const StatusPageHeader &header = *result.header;
            output << "VERSION=" << header.version << '\n';
            output << "SEQUENCE=" << header.sequence << '\n';
            output << "ENFORCING=" << header.enforcing << '\n';
            output << "POLICYLOAD=" << header.policyload << '\n';
            output << "DENY_UNKNOWN=" << header.deny_unknown << '\n';
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
Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxStatusPageProbe_nativeProbeStatusPage(
        JNIEnv *env,
        jobject
) {
    std::string payload;
    try {
        payload = encode_result(duckdetector::selinux::probe_selinux_status_page());
    } catch (const std::exception &error) {
        payload = failure_payload(std::string("Status page probe bridge failed: ") + error.what());
    } catch (...) {
        payload = failure_payload("Status page probe bridge failed with an unknown exception.");
    }
    return env->NewStringUTF(payload.c_str());
}
