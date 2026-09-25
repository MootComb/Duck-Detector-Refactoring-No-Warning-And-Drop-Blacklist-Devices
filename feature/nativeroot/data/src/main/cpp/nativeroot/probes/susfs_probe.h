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

#ifndef DUCKDETECTOR_NATIVEROOT_PROBES_SUSFS_PROBE_H
#define DUCKDETECTOR_NATIVEROOT_PROBES_SUSFS_PROBE_H

#include "nativeroot/common/types.h"

namespace duckdetector::nativeroot {

    // How the kernel answered the child's setresuid, carried in
    // ProbeResult::numeric_value. Bionic's app seccomp filter allows setresuid
    // (libc/SECCOMP_BLOCKLIST_APP.TXT), so the call reaches the kernel, which
    // denies it with EPERM for an unprivileged app.
    enum class SusfsOutcome : long {
        kNotObserved = 0,
        kDenied = 1,
        kKilled = 2,
        kChangedUid = 3,
    };

    ProbeResult run_susfs_probe();

}  // namespace duckdetector::nativeroot

#endif  // DUCKDETECTOR_NATIVEROOT_PROBES_SUSFS_PROBE_H
