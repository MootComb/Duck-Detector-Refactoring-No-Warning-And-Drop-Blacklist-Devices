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

#ifndef DUCKDETECTOR_SELINUXPOLICY_SELINUX_STATUS_ABI_PROBE_H
#define DUCKDETECTOR_SELINUXPOLICY_SELINUX_STATUS_ABI_PROBE_H

#include <cstdint>
#include <string>
#include <vector>

namespace duckdetector::selinux {

    enum class StatusAbiOutcome {
        // At least one request that stock selinuxfs rejects was granted on the status node.
        kViolation,
        // Every nonconforming request was rejected, like stock selinuxfs.
        kNoViolation,
        // The node could not be opened or its baseline mapping could not be established, so no
        // conformance request reached the status handler.
        kUnavailable,
        // No grant was reported and the child could not run or finish the request set,
        // so the handler's behavior on the remaining requests is unknown.
        kInconclusive,
    };

    // The four mmap/mprotect requests the upstream selinuxfs handler sel_mmap_handle_status
    // rejects (kernel/common security/selinux/selinuxfs.c, ACK 5.10 and 6.1): one page at offset 0,
    // read-only, with VM_MAYWRITE cleared after the mapping. Each request below breaks exactly one
    // of those constraints, so a handler that dropped the upstream checks answers differently.
    enum class StatusAbiRequest : uint8_t {
        // Two pages at offset 0: stock rejects the length, the replaced handler remaps one page.
        kTwoPageShared = 0,
        // One page at page offset 1: stock rejects a non-zero vm_pgoff.
        kOffsetShared = 1,
        // PROT_READ|PROT_WRITE MAP_PRIVATE: stock rejects VM_WRITE before remapping.
        kWritablePrivate = 2,
        // mprotect adding PROT_WRITE to the read-only baseline: stock cleared VM_MAYWRITE, so the
        // request fails with EACCES; a handler that keeps VM_MAYWRITE lets it through.
        kMprotectWrite = 3,
    };

    constexpr int kStatusAbiRequestCount = 4;

    // The result of sending each nonconforming request to /sys/fs/selinux/status from a forked
    // child. The child never dereferences any mapping it obtains: a request that is granted on a
    // hooked kernel can describe kernel memory, and only the kernel's accept/reject decision is
    // the evidence.
    struct StatusAbiProbeResult {
        bool attempted = false;
        StatusAbiOutcome outcome = StatusAbiOutcome::kInconclusive;
        // Per request: whether the kernel granted it, and the errno when it did not (-1 when the
        // request has no reported outcome).
        bool granted[kStatusAbiRequestCount] = {false, false, false, false};
        int request_error[kStatusAbiRequestCount] = {-1, -1, -1, -1};
        long page_size = 0;
        // A later child failure also accompanies kViolation when the request set is incomplete.
        std::string failure_reason;
        std::vector<std::string> notes;
    };

    StatusAbiProbeResult probe_selinux_status_abi();

}  // namespace duckdetector::selinux

#endif  // DUCKDETECTOR_SELINUXPOLICY_SELINUX_STATUS_ABI_PROBE_H
