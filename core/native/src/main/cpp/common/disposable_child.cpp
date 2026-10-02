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

#include "common/disposable_child.h"

#include "common/seccomp_child.h"

#include <cerrno>
#include <csignal>
#include <ctime>
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace duckdetector::common::detail {

    namespace {

        using Clock = std::chrono::steady_clock;
        using SigactionFn = int (*)(int, const struct sigaction *, struct sigaction *);

        // Next to kSeccompTrappedExitStatus (125), so neither reads as a status the body returned.
        constexpr int kSetupFailedExitStatus = 124;

        constexpr timespec kReapPollInterval{0, 1'000'000};

        // ART's libsigchain interposes sigaction(). For a signal ART claims, SIGSEGV and, under the
        // userfaultfd GC, SIGBUS (art/runtime/fault_handler.cc), it only records the new action and
        // keeps its own handler installed, and setting SIGSEGV to SIG_DFL also logs and unwinds the
        // caller's stack (art/sigchainlib/sigchain.cc, __sigaction). Neither restores the default
        // action, and unwinding allocates, which can deadlock a child forked from a multi-threaded
        // process. The child therefore calls bionic's sigaction, looked up before fork the way
        // libsigchain looks it up (lookup_libc_symbol).
        SigactionFn libc_sigaction() {
            static const SigactionFn resolved = []() -> SigactionFn {
                void *libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
                if (libc == nullptr) {
                    return nullptr;
                }
                auto *function = reinterpret_cast<SigactionFn>(dlsym(libc, "sigaction"));
                dlclose(libc);
                return function;
            }();
            return resolved;
        }

        // A fault would otherwise run the handler debuggerd installs in every app process and write a
        // tombstone for an expected, disposable failure. Without bionic's sigaction those handlers
        // stay, and a fault still ends the child, only with a tombstone; a SIGKILL runs none.
        void restore_default_fault_actions(const SigactionFn sigaction_fn) {
            if (sigaction_fn == nullptr) {
                return;
            }
            for (const int signal_number: {SIGSEGV, SIGBUS}) {
                struct sigaction action{};
                action.sa_handler = SIG_DFL;
                sigemptyset(&action.sa_mask);
                sigaction_fn(signal_number, &action, nullptr);
            }
        }

        [[noreturn]] void run_child(const int report_fd, const SigactionFn sigaction_fn,
                                    const ChildBody body, const void *context) {
            if (!install_seccomp_trap_exit()) {
                _exit(kSetupFailedExitStatus);
            }
            restore_default_fault_actions(sigaction_fn);
            _exit(body(context, report_fd));
        }

        // Copies what the child writes into report until the child closes its end, normally by
        // exiting, or the deadline passes. Bytes beyond the buffer are read and dropped, so the child
        // never blocks on a full pipe.
        void drain_report(const int fd, const std::span<unsigned char> report, std::size_t &length,
                          const Clock::time_point deadline) {
            unsigned char overflow[64];
            while (true) {
                const auto remaining =
                        std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now());
                if (remaining.count() <= 0) {
                    return;
                }
                pollfd poll_fd{fd, POLLIN, 0};
                const int ready = poll(&poll_fd, 1, static_cast<int>(remaining.count()));
                if (ready < 0 && errno == EINTR) {
                    continue;
                }
                if (ready <= 0) {
                    return;
                }
                const bool full = length >= report.size();
                const ssize_t count = full
                                      ? read(fd, overflow, sizeof(overflow))
                                      : read(fd, report.data() + length, report.size() - length);
                if (count < 0 && errno == EINTR) {
                    continue;
                }
                if (count <= 0) {
                    return;
                }
                if (!full) {
                    length += static_cast<std::size_t>(count);
                }
            }
        }

        enum class Reap {
            kReaped,
            kRunning,
            kFailed,
        };

        // Polls instead of blocking in waitpid: a child that will not die, even after SIGKILL, must
        // not hold up its parent.
        Reap reap_until(const pid_t pid, int &status, int &error, const Clock::time_point deadline) {
            while (true) {
                const pid_t waited = waitpid(pid, &status, WNOHANG);
                if (waited == pid) {
                    return Reap::kReaped;
                }
                if (waited < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    error = errno;
                    return Reap::kFailed;
                }
                if (Clock::now() >= deadline) {
                    return Reap::kRunning;
                }
                nanosleep(&kReapPollInterval, nullptr);
            }
        }

        ChildOutcome classify(const int status, ChildOutcome outcome) {
            // Without WUNTRACED or WCONTINUED, waitpid reports only children that terminated, so a child
            // that was not signaled exited.
            if (seccomp_trapped(status)) {
                outcome.end = ChildEnd::kSeccompTrapped;
            } else if (WIFSIGNALED(status)) {
                outcome.end = ChildEnd::kSignaled;
                outcome.signal = WTERMSIG(status);
            } else if (WEXITSTATUS(status) == kSetupFailedExitStatus) {
                outcome.end = ChildEnd::kSetupFailed;
            } else {
                outcome.end = ChildEnd::kExited;
                outcome.exit_status = WEXITSTATUS(status);
            }
            return outcome;
        }

    }  // namespace

    ChildOutcome run_disposable_child(const std::span<unsigned char> report,
                                      const ChildDeadlines deadlines,
                                      const ChildBody body,
                                      const void *context) {
        ChildOutcome outcome;
        const SigactionFn sigaction_fn = libc_sigaction();

        int pipe_fds[2] = {-1, -1};
        if (pipe2(pipe_fds, O_CLOEXEC) != 0) {
            outcome.error = errno;
            return outcome;
        }
        const pid_t pid = fork();
        if (pid < 0) {
            outcome.error = errno;
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            return outcome;
        }
        if (pid == 0) {
            close(pipe_fds[0]);
            run_child(pipe_fds[1], sigaction_fn, body, context);
        }
        close(pipe_fds[1]);

        const Clock::time_point run_deadline = Clock::now() + deadlines.run;
        drain_report(pipe_fds[0], report, outcome.report_length, run_deadline);
        int status = 0;
        Reap reap = reap_until(pid, status, outcome.error, run_deadline);
        const bool stopped = reap == Reap::kRunning;
        if (stopped) {
            kill(pid, SIGKILL);
            reap = reap_until(pid, status, outcome.error, Clock::now() + deadlines.reap);
        }
        close(pipe_fds[0]);

        switch (reap) {
            case Reap::kFailed:
                outcome.end = ChildEnd::kWaitFailed;
                return outcome;
            case Reap::kRunning:
                outcome.end = ChildEnd::kNotReaped;
                return outcome;
            case Reap::kReaped:
                break;
        }
        if (stopped) {
            // The SIGKILL is the parent's, so the status says nothing about what the body did.
            outcome.end = ChildEnd::kTimedOut;
            return outcome;
        }
        return classify(status, outcome);
    }

}  // namespace duckdetector::common::detail
