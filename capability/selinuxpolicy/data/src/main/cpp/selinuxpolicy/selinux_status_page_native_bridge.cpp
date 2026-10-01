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

#include <jni.h>

#include <exception>
#include <sstream>
#include <string>

#include "common/payload_codec.h"
#include "selinuxpolicy/selinux_status_page_probe.h"

namespace {

    using duckdetector::selinux::StatusPageOutcome;
    using duckdetector::selinux::StatusPageProbeResult;

    const char *outcome_name(const StatusPageOutcome outcome) {
        switch (outcome) {
            case StatusPageOutcome::kIntact:
                return "INTACT";
            case StatusPageOutcome::kHostile:
                return "HOSTILE";
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
        if (result.version.has_value()) {
            output << "VERSION=" << *result.version << '\n';
        }
        if (result.sequence.has_value()) {
            output << "SEQUENCE=" << *result.sequence << '\n';
        }
        if (result.enforcing.has_value()) {
            output << "ENFORCING=" << *result.enforcing << '\n';
        }
        if (result.policyload.has_value()) {
            output << "POLICYLOAD=" << *result.policyload << '\n';
        }
        if (result.deny_unknown.has_value()) {
            output << "DENY_UNKNOWN=" << *result.deny_unknown << '\n';
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
