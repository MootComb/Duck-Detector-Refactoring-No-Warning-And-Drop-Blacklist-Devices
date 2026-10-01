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

#include "selinuxpolicy/selinux_status_page_probe.h"

#include "common/seccomp_child.h"

#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <string>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace duckdetector::selinux {

    namespace {

        // libselinux opens and maps this node the first time it checks an access decision
        // (external/selinux libselinux/src/sestatus.c, selinux_status_open, reached through
        // checkAccess.c selinux_check_access -> avc_open -> avc.c avc_init_internal).
        constexpr const char *kStatusPagePath = "/sys/fs/selinux/status";

        // struct selinux_kernel_status: version, sequence, enforcing, policyload, deny_unknown,
        // each a u32 (kernel/common security/selinux/ss/status.c).
        constexpr std::size_t kStatusHeaderBytes = 20;

        // The read finishes in microseconds on any kernel that answers it. system_server waits on
        // the app_zygote preload without a timeout, so a child that never returns must not stall it.
        constexpr int kChildTimeoutMs = 1000;

        // An odd sequence means the kernel was mid-update (sestatus.c, read_sequence), so the read is
        // retried up to three more times, 2 ms apart.
        constexpr int kHeaderReadAttempts = 4;
        constexpr long kOddSequencePauseNs = 2L * 1000L * 1000L;

        constexpr int kOpenFailedExit = 10;
        constexpr int kMmapFailedExit = 11;

        constexpr char kOpenFailedTag = 'O';
        constexpr char kMmapFailedTag = 'M';
        constexpr char kReadTag = 'R';

        using SigactionFn = int (*)(int, const struct sigaction *, struct sigaction *);

        // ART's libsigchain interposes sigaction() to keep its own fault handler in front, and when
        // SIGSEGV is reset it logs and unwinds the caller's stack, which allocates: unsafe in a child
        // forked from a multi-threaded process. The child never runs managed code again, so it calls
        // bionic's sigaction directly, found before fork the way libsigchain finds it
        // (art/sigchainlib/sigchain.cc, lookup_libc_symbol).
        SigactionFn resolve_libc_sigaction() {
            void *libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
            if (libc == nullptr) {
                return nullptr;
            }
            auto *libc_sigaction = reinterpret_cast<SigactionFn>(dlsym(libc, "sigaction"));
            dlclose(libc);
            return libc_sigaction;
        }

        void reset_fault_signals(const SigactionFn libc_sigaction) {
            // A read fault would otherwise run the SIGSEGV/SIGBUS handler debuggerd installs in every
            // app process, writing a tombstone for an expected, disposable failure. With the default
            // action the child simply dies and the parent reads the signal from waitpid. Without
            // bionic's sigaction the handlers stay; a SIGKILL, as on the reported kernel, runs none.
            if (libc_sigaction == nullptr) {
                return;
            }
            for (const int signal_number: {SIGSEGV, SIGBUS}) {
                struct sigaction action{};
                action.sa_handler = SIG_DFL;
                sigemptyset(&action.sa_mask);
                libc_sigaction(signal_number, &action, nullptr);
            }
        }

        void write_all(const int fd, const void *data, const std::size_t length) {
            const auto *bytes = static_cast<const unsigned char *>(data);
            std::size_t written = 0;
            while (written < length) {
                const ssize_t result = write(fd, bytes + written, length - written);
                if (result < 0 && errno == EINTR) {
                    continue;
                }
                if (result <= 0) {
                    return;
                }
                written += static_cast<std::size_t>(result);
            }
        }

        void report_errno(const int fd, const char tag, const int error) {
            write_all(fd, &tag, sizeof(tag));
            write_all(fd, &error, sizeof(error));
        }

        // Runs only in the forked child. The app_zygote is multi-threaded under ART when it forks,
        // so the child calls nothing that could take a lock another thread held at fork time: only
        // sigaction, open, mmap, close, nanosleep, write and _exit, which are async-signal-safe.
        [[noreturn]] void run_child(const char *path, const int report_fd, const long page_size,
                                    const SigactionFn libc_sigaction) {
            if (!common::install_seccomp_trap_exit()) {
                _exit(1);
            }
            reset_fault_signals(libc_sigaction);

            const int fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                report_errno(report_fd, kOpenFailedTag, errno);
                _exit(kOpenFailedExit);
            }
            void *mapping = mmap(nullptr, static_cast<std::size_t>(page_size), PROT_READ,
                                 MAP_SHARED, fd, 0);
            const int mmap_error = errno;
            close(fd);
            if (mapping == MAP_FAILED) {
                report_errno(report_fd, kMmapFailedTag, mmap_error);
                _exit(kMmapFailedExit);
            }

            // The first load from the mapping is where a hooked open handler faults. libselinux makes
            // the same load right after mmap (sestatus.c, read_sequence), so a kill here is the kill
            // the carrier would take. volatile keeps the compiler from eliding or merging the loads.
            const auto *source = static_cast<const volatile unsigned char *>(mapping);
            unsigned char header[kStatusHeaderBytes];
            for (int attempt = 0; attempt < kHeaderReadAttempts; ++attempt) {
                for (std::size_t index = 0; index < kStatusHeaderBytes; ++index) {
                    header[index] = source[index];
                }
                // Every Android ABI is little-endian, so byte 4 holds the sequence's low bit.
                if ((header[4] & 1U) == 0) {
                    break;
                }
                const timespec pause{0, kOddSequencePauseNs};
                nanosleep(&pause, nullptr);
            }
            write_all(report_fd, &kReadTag, sizeof(kReadTag));
            write_all(report_fd, header, sizeof(header));
            _exit(0);
        }

        long long monotonic_ms() {
            timespec now{};
            clock_gettime(CLOCK_MONOTONIC, &now);
            return static_cast<long long>(now.tv_sec) * 1000LL + now.tv_nsec / 1000000LL;
        }

        // Reads what the child wrote until it exits (closing the pipe) or the deadline passes.
        // Returns false when the deadline passed with the child still running.
        bool drain_report(const int fd, unsigned char *buffer, const std::size_t capacity,
                          std::size_t &length) {
            const long long deadline = monotonic_ms() + kChildTimeoutMs;
            while (true) {
                const long long remaining = deadline - monotonic_ms();
                if (remaining <= 0) {
                    return false;
                }
                pollfd poll_fd{fd, POLLIN, 0};
                const int ready = poll(&poll_fd, 1, static_cast<int>(remaining));
                if (ready < 0 && errno == EINTR) {
                    continue;
                }
                if (ready <= 0) {
                    return false;
                }
                if (length >= capacity) {
                    unsigned char discard[64];
                    if (read(fd, discard, sizeof(discard)) <= 0) {
                        return true;
                    }
                    continue;
                }
                const ssize_t result = read(fd, buffer + length, capacity - length);
                if (result < 0 && errno == EINTR) {
                    continue;
                }
                if (result <= 0) {
                    return true;
                }
                length += static_cast<std::size_t>(result);
            }
        }

        int wait_for_child(const pid_t pid, int &status) {
            pid_t waited = 0;
            do {
                waited = waitpid(pid, &status, 0);
            } while (waited < 0 && errno == EINTR);
            return waited < 0 ? errno : 0;
        }

        uint32_t read_le32(const unsigned char *bytes) {
            return static_cast<uint32_t>(bytes[0]) |
                   (static_cast<uint32_t>(bytes[1]) << 8) |
                   (static_cast<uint32_t>(bytes[2]) << 16) |
                   (static_cast<uint32_t>(bytes[3]) << 24);
        }

        std::string signal_name(const int signal_number) {
            switch (signal_number) {
                case SIGKILL:
                    return "SIGKILL";
                case SIGSEGV:
                    return "SIGSEGV";
                case SIGBUS:
                    return "SIGBUS";
                default:
                    return "signal " + std::to_string(signal_number);
            }
        }

        void classify_exit(const char *path, const int exit_code, const unsigned char *report,
                           const std::size_t report_length, StatusPageProbeResult &result) {
            if (exit_code == kOpenFailedExit || exit_code == kMmapFailedExit) {
                int error = 0;
                if (report_length >= 1 + sizeof(error)) {
                    std::memcpy(&error, report + 1, sizeof(error));
                }
                result.outcome = StatusPageOutcome::kUnavailable;
                result.failure_reason =
                        std::string(exit_code == kOpenFailedExit ? "open" : "mmap") + " of " +
                        path + " failed (errno=" + std::to_string(error) + ").";
                result.notes.emplace_back(
                        "libselinux falls back to netlink when it cannot map the status page, so "
                        "access checks in the carrier stay safe.");
                return;
            }
            if (exit_code != 0 || report_length < 1 + kStatusHeaderBytes || report[0] != kReadTag) {
                result.failure_reason = "Status page child exited " + std::to_string(exit_code) +
                                        " without reporting the header.";
                return;
            }
            const unsigned char *header = report + 1;
            result.outcome = StatusPageOutcome::kIntact;
            result.version = read_le32(header);
            result.sequence = read_le32(header + 4);
            result.enforcing = read_le32(header + 8);
            result.policyload = read_le32(header + 12);
            result.deny_unknown = read_le32(header + 16);
            result.notes.emplace_back(
                    "Status page read back: version=" + std::to_string(*result.version) +
                    " sequence=" + std::to_string(*result.sequence) +
                    " enforcing=" + std::to_string(*result.enforcing) +
                    " policyload=" + std::to_string(*result.policyload) +
                    " deny_unknown=" + std::to_string(*result.deny_unknown) + ".");
        }

        // The path is a parameter so the fork and wait handling can be driven against files whose
        // mapping faults, hangs or fails; production only ever passes kStatusPagePath.
        StatusPageProbeResult probe_status_page_at(const char *path) {
            StatusPageProbeResult result;

            const long page_size = sysconf(_SC_PAGESIZE);
            if (page_size <= 0) {
                result.failure_reason = "Page size unavailable; status page probe not run.";
                return result;
            }

            const SigactionFn libc_sigaction = resolve_libc_sigaction();

            int pipe_fds[2] = {-1, -1};
            if (pipe2(pipe_fds, O_CLOEXEC) != 0) {
                result.failure_reason = "pipe2 failed (errno=" + std::to_string(errno) +
                                        "); status page probe not run.";
                return result;
            }

            const pid_t pid = fork();
            if (pid < 0) {
                const int fork_error = errno;
                close(pipe_fds[0]);
                close(pipe_fds[1]);
                result.failure_reason = "fork failed (errno=" + std::to_string(fork_error) +
                                        "); status page probe not run.";
                return result;
            }
            if (pid == 0) {
                close(pipe_fds[0]);
                run_child(path, pipe_fds[1], page_size, libc_sigaction);
            }

            close(pipe_fds[1]);
            result.attempted = true;

            unsigned char report[1 + kStatusHeaderBytes] = {};
            std::size_t report_length = 0;
            const bool finished = drain_report(pipe_fds[0], report, sizeof(report), report_length);
            close(pipe_fds[0]);
            if (!finished) {
                kill(pid, SIGKILL);
            }

            int status = 0;
            if (const int wait_error = wait_for_child(pid, status); wait_error != 0) {
                result.failure_reason = "waitpid failed (errno=" + std::to_string(wait_error) +
                                        "); status page outcome unknown.";
                return result;
            }
            if (!finished) {
                // The SIGKILL is ours, so it says nothing about the page.
                result.failure_reason = "Status page child did not finish within " +
                                        std::to_string(kChildTimeoutMs) + " ms and was stopped.";
                return result;
            }
            if (common::seccomp_trapped(status)) {
                result.failure_reason = "Seccomp refused a status page syscall in the child.";
                return result;
            }
            if (WIFSIGNALED(status)) {
                result.outcome = StatusPageOutcome::kHostile;
                result.terminating_signal = WTERMSIG(status);
                result.notes.emplace_back(
                        "Child opened and mapped " + std::string(path) + ", then was killed by " +
                        signal_name(result.terminating_signal) + " on the first read of the mapping.");
                result.notes.emplace_back(
                        "Stock selinuxfs maps the kernel's status page, which reads back without faulting.");
                return result;
            }
            if (!WIFEXITED(status)) {
                result.failure_reason = "Status page child ended without an exit status.";
                return result;
            }
            classify_exit(path, WEXITSTATUS(status), report, report_length, result);
            return result;
        }

    }  // namespace

    StatusPageProbeResult probe_selinux_status_page() {
        return probe_status_page_at(kStatusPagePath);
    }

    bool status_page_allows_in_process_access(const StatusPageProbeResult &result) {
        return result.outcome == StatusPageOutcome::kIntact ||
               result.outcome == StatusPageOutcome::kUnavailable;
    }

}  // namespace duckdetector::selinux
