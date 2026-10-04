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

#ifndef DUCKDETECTOR_SELINUXPOLICY_SELINUX_STATUS_PAGE_PROBE_H
#define DUCKDETECTOR_SELINUXPOLICY_SELINUX_STATUS_PAGE_PROBE_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace duckdetector::selinux {

    enum class StatusPageOutcome {
        // The status page opened, mapped and read back like stock selinuxfs.
        kIntact,
        // A disposable child mapped the page and a signal ended it before it read the header back:
        // the node's open handler returned a mapping that faults, which stock selinuxfs never does.
        kFaulted,
        // open or mmap failed. libselinux then falls back to netlink instead of reading a mapping,
        // so access checks in the carrier cannot fault on the page.
        kUnavailable,
        // The child could not run, ended before it mapped the page, or did not report (fork, wait
        // or seccomp failure, timeout), so whether reading the page would fault is unknown.
        kInconclusive,
    };

    // struct selinux_kernel_status (kernel/common security/selinux/include/security.h).
    struct StatusPageHeader {
        uint32_t version = 0;
        uint32_t sequence = 0;
        uint32_t enforcing = 0;
        uint32_t policyload = 0;
        uint32_t deny_unknown = 0;
    };

    // The result of reproducing, inside a forked child, exactly the operation libselinux performs
    // when it first checks an access decision: open `/sys/fs/selinux/status`, mmap one page and read
    // the header. The child is disposable so a kill lands on it, not on the app_zygote carrier.
    struct StatusPageProbeResult {
        bool attempted = false;
        StatusPageOutcome outcome = StatusPageOutcome::kInconclusive;
        // The signal that ended the child when the outcome is kFaulted, else 0.
        int terminating_signal = 0;
        // The header the child read, present only when the outcome is kIntact.
        std::optional<StatusPageHeader> header;
        std::string failure_reason;
        std::vector<std::string> notes;
    };

    StatusPageProbeResult probe_selinux_status_page();

}  // namespace duckdetector::selinux

#endif  // DUCKDETECTOR_SELINUXPOLICY_SELINUX_STATUS_PAGE_PROBE_H
