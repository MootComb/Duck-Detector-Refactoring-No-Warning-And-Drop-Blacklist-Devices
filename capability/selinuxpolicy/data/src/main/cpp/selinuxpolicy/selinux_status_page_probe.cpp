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

#include "selinuxpolicy/selinux_status_page_probe.h"

#include "common/disposable_child.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <span>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace duckdetector::selinux {

    namespace {

        // libselinux opens and maps this node the first time it checks an access decision
        // (external/selinux libselinux/src/sestatus.c, selinux_status_open, reached through
        // checkAccess.c selinux_check_access -> avc_open -> avc.c avc_init_internal).
        constexpr const char *kStatusPagePath = "/sys/fs/selinux/status";

        constexpr std::size_t kStatusHeaderBytes = 5 * sizeof(uint32_t);

        // The read finishes in microseconds on any kernel that answers it. system_server waits on
        // the app_zygote preload without a timeout, so a child that never returns must not stall it.
        constexpr common::ChildDeadlines kChildDeadlines{
                .run = std::chrono::milliseconds(1000),
                .reap = std::chrono::milliseconds(250),
        };

        // An odd sequence means the kernel was mid-update (sestatus.c, read_sequence), so the read is
        // retried up to three more times, 2 ms apart.
        constexpr int kHeaderReadAttempts = 4;
        constexpr timespec kOddSequencePause{0, 2'000'000};

        // How far the child got. It writes a whole report after each step, in one write smaller than
        // PIPE_BUF, so the parent learns the last step reached even when a signal ends the child.
        enum class ChildStep : uint8_t {
            kOpenFailed = 1,
            kMmapFailed,
            // Written just before the first load from the mapping, where a broken open handler
            // faults, so that only a signal after this step is attributed to the read.
            kMapped,
            kRead,
        };

        struct ChildReport {
            ChildStep step;
            int error;
            unsigned char header[kStatusHeaderBytes];
        };

        void send(const int fd, const ChildReport &report) {
            const auto *bytes = reinterpret_cast<const unsigned char *>(&report);
            std::size_t written = 0;
            while (written < sizeof(report)) {
                const ssize_t result = write(fd, bytes + written, sizeof(report) - written);
                if (result < 0 && errno == EINTR) {
                    continue;
                }
                if (result <= 0) {
                    return;
                }
                written += static_cast<std::size_t>(result);
            }
        }

        // The disposable child's body: only open, mmap, close, nanosleep and write, which are
        // async-signal-safe.
        int read_status_page(const char *path, const long page_size, const int report_fd) {
            ChildReport report{};
            const int fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                report.step = ChildStep::kOpenFailed;
                report.error = errno;
                send(report_fd, report);
                return 0;
            }
            void *mapping = mmap(nullptr, static_cast<std::size_t>(page_size), PROT_READ,
                                 MAP_SHARED, fd, 0);
            const int mmap_error = errno;
            close(fd);
            if (mapping == MAP_FAILED) {
                report.step = ChildStep::kMmapFailed;
                report.error = mmap_error;
                send(report_fd, report);
                return 0;
            }
            report.step = ChildStep::kMapped;
            send(report_fd, report);

            // libselinux makes the same load right after mmap (sestatus.c, read_sequence), so a kill
            // here is the kill the carrier would take. volatile keeps the loads from being elided or
            // merged.
            const auto *source = static_cast<const volatile unsigned char *>(mapping);
            for (int attempt = 0; attempt < kHeaderReadAttempts; ++attempt) {
                for (std::size_t index = 0; index < kStatusHeaderBytes; ++index) {
                    report.header[index] = source[index];
                }
                // Every Android ABI is little-endian, so byte 4 holds the sequence's low bit.
                if ((report.header[4] & 1U) == 0) {
                    break;
                }
                nanosleep(&kOddSequencePause, nullptr);
            }
            report.step = ChildStep::kRead;
            send(report_fd, report);
            return 0;
        }

        std::optional<ChildReport> last_report(const std::span<const unsigned char> bytes) {
            if (bytes.size() < sizeof(ChildReport)) {
                return std::nullopt;
            }
            ChildReport report{};
            const std::size_t offset = (bytes.size() / sizeof(ChildReport) - 1) * sizeof(ChildReport);
            std::memcpy(&report, bytes.data() + offset, sizeof(report));
            return report;
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

        StatusPageProbeResult intact(const ChildReport &report) {
            StatusPageProbeResult result;
            result.attempted = true;
            result.outcome = StatusPageOutcome::kIntact;
            const StatusPageHeader header{
                    .version = read_le32(report.header),
                    .sequence = read_le32(report.header + 4),
                    .enforcing = read_le32(report.header + 8),
                    .policyload = read_le32(report.header + 12),
                    .deny_unknown = read_le32(report.header + 16),
            };
            result.header = header;
            result.notes.push_back(
                    "Status page read back: version=" + std::to_string(header.version) +
                    " sequence=" + std::to_string(header.sequence) +
                    " enforcing=" + std::to_string(header.enforcing) +
                    " policyload=" + std::to_string(header.policyload) +
                    " deny_unknown=" + std::to_string(header.deny_unknown) + ".");
            return result;
        }

        StatusPageProbeResult unavailable(const char *path, const ChildReport &report) {
            StatusPageProbeResult result;
            result.attempted = true;
            result.outcome = StatusPageOutcome::kUnavailable;
            result.failure_reason =
                    std::string(report.step == ChildStep::kOpenFailed ? "open" : "mmap") + " of " +
                    path + " failed (errno=" + std::to_string(report.error) + ").";
            result.notes.emplace_back(
                    "libselinux falls back to netlink when it cannot map the status page, so access "
                    "checks in the carrier stay safe.");
            return result;
        }

        StatusPageProbeResult faulted(const char *path, const int signal_number) {
            StatusPageProbeResult result;
            result.attempted = true;
            result.outcome = StatusPageOutcome::kFaulted;
            result.terminating_signal = signal_number;
            result.notes.push_back(
                    "Child opened and mapped " + std::string(path) + ", then was killed by " +
                    signal_name(signal_number) + " on the first read of the mapping.");
            result.notes.emplace_back(
                    "Stock selinuxfs maps the kernel's status page, which reads back without faulting.");
            return result;
        }

        std::string inconclusive_reason(const common::ChildOutcome &child, const bool mapped) {
            const std::string run_ms = std::to_string(kChildDeadlines.run.count());
            switch (child.end) {
                case common::ChildEnd::kNotStarted:
                    return "Status page child could not be started (errno=" +
                           std::to_string(child.error) + "); status page probe not run.";
                case common::ChildEnd::kSetupFailed:
                    return "Status page child could not install its seccomp trap exit.";
                case common::ChildEnd::kSeccompTrapped:
                    return "Seccomp refused a status page syscall in the child.";
                case common::ChildEnd::kSignaled:
                    return "Status page child was killed by " + signal_name(child.signal) +
                           " before it mapped the page.";
                case common::ChildEnd::kTimedOut:
                    return mapped
                           ? "Status page child mapped the page but did not read it within " +
                             run_ms + " ms and was stopped."
                           : "Status page child did not finish within " + run_ms +
                             " ms and was stopped.";
                case common::ChildEnd::kNotReaped:
                    return "Status page child did not finish within " + run_ms +
                           " ms, and was left behind because it had not died " +
                           std::to_string(kChildDeadlines.reap.count()) + " ms after it was stopped.";
                case common::ChildEnd::kWaitFailed:
                    return "waitpid failed (errno=" + std::to_string(child.error) +
                           "); status page outcome unknown.";
                case common::ChildEnd::kExited:
                    break;
            }
            return "Status page child exited " + std::to_string(child.exit_status) +
                   " without reporting the header.";
        }

        // What the child reported settles intact and unavailable whoever reaped it; only a child that
        // stopped reporting needs its end to be read, and only a signal after the mapping is a fault.
        StatusPageProbeResult interpret(const char *path, const common::ChildOutcome &child,
                                        const std::optional<ChildReport> &report) {
            const std::optional<ChildStep> step =
                    report.has_value() ? std::optional(report->step) : std::nullopt;
            if (step == ChildStep::kRead) {
                return intact(*report);
            }
            if (step == ChildStep::kOpenFailed || step == ChildStep::kMmapFailed) {
                return unavailable(path, *report);
            }
            const bool mapped = step == ChildStep::kMapped;
            if (mapped && child.end == common::ChildEnd::kSignaled) {
                return faulted(path, child.signal);
            }
            StatusPageProbeResult result;
            result.attempted = child.end != common::ChildEnd::kNotStarted;
            result.failure_reason = inconclusive_reason(child, mapped);
            return result;
        }

        // The path is a parameter so the probe can be driven against files whose mapping faults,
        // hangs or fails; production only ever passes kStatusPagePath.
        StatusPageProbeResult probe_status_page_at(const char *path) {
            const long page_size = sysconf(_SC_PAGESIZE);
            if (page_size <= 0) {
                StatusPageProbeResult result;
                result.failure_reason = "Page size unavailable; status page probe not run.";
                return result;
            }
            std::array<unsigned char, 4 * sizeof(ChildReport)> buffer{};
            const common::ChildOutcome child = common::run_disposable_child(
                    buffer,
                    kChildDeadlines,
                    [path, page_size](const int report_fd) {
                        return read_status_page(path, page_size, report_fd);
                    }
            );
            return interpret(path, child, last_report(std::span(buffer).first(child.report_length)));
        }

    }  // namespace

    StatusPageProbeResult probe_selinux_status_page() {
        return probe_status_page_at(kStatusPagePath);
    }

}  // namespace duckdetector::selinux
