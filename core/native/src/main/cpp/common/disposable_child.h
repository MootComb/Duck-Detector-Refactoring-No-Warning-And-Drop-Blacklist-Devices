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

#ifndef DUCKDETECTOR_COMMON_DISPOSABLE_CHILD_H
#define DUCKDETECTOR_COMMON_DISPOSABLE_CHILD_H

#include <chrono>
#include <cstddef>
#include <memory>
#include <span>

namespace duckdetector::common {

    // How a disposable child ended, as far as its parent could tell.
    enum class ChildEnd {
        // pipe2 or fork failed, so nothing ran; ChildOutcome::error holds errno.
        kNotStarted,
        // The child could not install its seccomp trap exit and exited before the body ran.
        kSetupFailed,
        // The body returned; ChildOutcome::exit_status holds what it returned.
        kExited,
        // A signal ended the child; ChildOutcome::signal holds it.
        kSignaled,
        // Seccomp refused one of the child's syscalls (seccomp_child.h).
        kSeccompTrapped,
        // The child was still running at the run deadline, so the parent stopped it with SIGKILL.
        kTimedOut,
        // The stopped child had not died by the reap deadline, as when it sleeps uninterruptibly in
        // the kernel, so the parent left it behind instead of blocking on it.
        kNotReaped,
        // waitpid failed; ChildOutcome::error holds errno.
        kWaitFailed,
    };

    struct ChildOutcome {
        ChildEnd end = ChildEnd::kNotStarted;
        int exit_status = 0;
        int signal = 0;
        int error = 0;
        // How much of the report buffer the child filled; what it wrote beyond the buffer is dropped.
        std::size_t report_length = 0;
    };

    struct ChildDeadlines {
        // How long the child may run before the parent stops it.
        std::chrono::milliseconds run{1000};
        // How long the parent then waits for the stopped child to die before leaving it behind.
        std::chrono::milliseconds reap{250};
    };

    namespace detail {

        using ChildBody = int (*)(const void *context, int report_fd);

        ChildOutcome run_disposable_child(std::span<unsigned char> report, ChildDeadlines deadlines,
                                          ChildBody body, const void *context);

    }  // namespace detail

    // Runs body(report_fd) in a forked child, so that a fault, a seccomp trap or a kill ends only the
    // child, and returns how the child ended with the bytes it wrote to report_fd. The parent never
    // waits longer than the run and reap deadlines together.
    //
    // The child is forked from a multi-threaded process, so the body may call only async-signal-safe
    // functions and must not allocate. What it returns becomes the exit status and must stay below
    // 124; 124 and 125 are reserved. Before the body runs, the child installs the seccomp trap exit and
    // restores the default action of SIGSEGV and SIGBUS, so a fault ends it without a tombstone and
    // the parent reads the signal instead.
    template<typename Body>
    ChildOutcome run_disposable_child(std::span<unsigned char> report, const ChildDeadlines deadlines,
                                      const Body &body) {
        return detail::run_disposable_child(
                report,
                deadlines,
                [](const void *context, const int report_fd) -> int {
                    return (*static_cast<const Body *>(context))(report_fd);
                },
                std::addressof(body)
        );
    }

}  // namespace duckdetector::common

#endif  // DUCKDETECTOR_COMMON_DISPOSABLE_CHILD_H
