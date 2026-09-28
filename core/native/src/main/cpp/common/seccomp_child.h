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

#ifndef DUCKDETECTOR_COMMON_SECCOMP_CHILD_H
#define DUCKDETECTOR_COMMON_SECCOMP_CHILD_H

#include <csignal>
#include <sys/wait.h>
#include <unistd.h>

namespace duckdetector::common {

    // Probes fork a child to issue a syscall the app's seccomp filter may refuse, so that the
    // refusal ends only the child. The filter refuses by trapping (SECCOMP_RET_TRAP, delivered as
    // SIGSYS), and every process inherits the SIGSYS handler debuggerd registers
    // (system/core debuggerd/include/debuggerd/handler.h, debuggerd_register_handlers), which
    // writes a tombstone: an expected refusal would still be reported as a native crash of the
    // app. A child that installs this handler exits with kSeccompTrappedExitStatus instead.
    inline constexpr int kSeccompTrappedExitStatus = 125;

    inline void exit_on_seccomp_trap(int, siginfo_t *, void *) {
        _exit(kSeccompTrappedExitStatus);
    }

    // Call in the forked child before its first syscall; false means the handler is not in place.
    inline bool install_seccomp_trap_exit() {
        struct sigaction action{};
        action.sa_sigaction = exit_on_seccomp_trap;
        action.sa_flags = SA_SIGINFO;
        sigemptyset(&action.sa_mask);
        return sigaction(SIGSYS, &action, nullptr) == 0;
    }

    // Whether a waitpid() status shows that seccomp refused the child a syscall.
    inline bool seccomp_trapped(int status) {
        return (WIFEXITED(status) && WEXITSTATUS(status) == kSeccompTrappedExitStatus) ||
               (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS);
    }

}  // namespace duckdetector::common

#endif  // DUCKDETECTOR_COMMON_SECCOMP_CHILD_H
