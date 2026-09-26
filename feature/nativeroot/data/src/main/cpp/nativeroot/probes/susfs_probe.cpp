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

#include "nativeroot/probes/susfs_probe.h"

#include <cerrno>
#include <csignal>
#include <sstream>
#include <string>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace duckdetector::nativeroot {

    ProbeResult run_susfs_probe() {
        ProbeResult result;

        result.numeric_value = static_cast<long>(SusfsOutcome::kNotObserved);

        const uid_t current_uid = getuid();
        if (current_uid == 0) {
            result.extra_text = "Not run: the process already has uid 0.";
            return result;
        }

        uid_t target_uid = 0;
        if (current_uid >= 10000) {
            target_uid = current_uid > 10000 ? 10000 : static_cast<uid_t>(current_uid - 1);
        } else if (current_uid > 0) {
            target_uid = static_cast<uid_t>(current_uid - 1);
        }
        if (target_uid >= current_uid) {
            result.extra_text = "Not run: no lower uid to request.";
            return result;
        }

        const pid_t pid = fork();
        if (pid < 0) {
            result.extra_text = "Not run: fork failed (errno=" + std::to_string(errno) + ").";
            return result;
        }

        if (pid == 0) {
            const long syscall_result = syscall(__NR_setresuid, target_uid, target_uid, target_uid);
            _exit(syscall_result == 0 ? 100 : 0);
        }

        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            result.extra_text = "Not observed: waitpid failed (errno=" + std::to_string(errno) + ").";
            return result;
        }

        std::ostringstream detail;
        detail << "Current UID " << current_uid << ", attempted setresuid(" << target_uid << ").";

        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
            result.numeric_value = static_cast<long>(SusfsOutcome::kKilled);
            result.flags.kernel_su = true;
            result.flags.susfs = true;
            result.hit_count = 1;
            detail << " Child was killed by SIGKILL instead of returning EPERM.";
            result.findings.push_back(
                    Finding{
                            .group = "SIDE_CHANNEL",
                            .label = "SUSFS side-channel",
                            .value = "SIGKILL",
                            .detail = detail.str(),
                            .severity = Severity::kDanger,
                    }
            );
            return result;
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) == 100) {
            result.numeric_value = static_cast<long>(SusfsOutcome::kChangedUid);
            result.hit_count = 1;
            detail << " Child unexpectedly changed UID successfully.";
            result.findings.push_back(
                    Finding{
                            .group = "SIDE_CHANNEL",
                            .label = "setresuid privilege change",
                            .value = "Unexpected success",
                            .detail = detail.str(),
                            .severity = Severity::kDanger,
                    }
            );
            return result;
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            result.numeric_value = static_cast<long>(SusfsOutcome::kDenied);
            detail << " The kernel refused it, as it should for an unprivileged app.";
        } else {
            detail << " The child ended without reporting how the kernel answered.";
        }
        result.extra_text = detail.str();
        return result;
    }

}  // namespace duckdetector::nativeroot
