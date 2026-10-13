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

#include "selinuxpolicy/selinux_status_abi_probe.h"

#include "common/disposable_child.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <span>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace duckdetector::selinux {

    namespace {

        // The node whose mmap handler the probe interrogates. libselinux maps it on the first
        // access check (external/selinux libselinux/src/sestatus.c, selinux_status_open).
        constexpr const char *kStatusNodePath = "/sys/fs/selinux/status";

        // The requests complete in microseconds on any kernel that answers them. system_server
        // waits on the app_zygote preload without a timeout, so a child that never returns must
        // not stall it.
        constexpr common::ChildDeadlines kChildDeadlines{
                .run = std::chrono::milliseconds(1000),
                .reap = std::chrono::milliseconds(250),
        };

        // How far the child got. It writes a whole report after each step, in one write smaller
        // than PIPE_BUF, so the parent learns the last step reached even when a signal ends the
        // child.
        enum class ChildStep : uint8_t {
            kOpenFailed = 1,
            kBaselineMmapFailed,
            // Written once the baseline one-page read-only mapping exists, before the first
            // nonconforming request.
            kBaselineMapped,
            // Written after each conformance request, with which request ran and what it returned.
            kRequest,
            kDone,
        };

        struct ChildReport {
            ChildStep step;
            uint8_t request;
            uint8_t granted;
            int32_t error;
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

        // The disposable child's body: only open, mmap, mprotect, munmap, close and write, which
        // are async-signal-safe. No granted mapping is ever dereferenced: on a hooked kernel a
        // granted request can describe kernel memory, and only the accept/reject decision is
        // evidence. The mprotect request runs last so the baseline is not reused after it.
        int run_abi_requests(const char *path, const long page_size, const int report_fd) {
            const auto page = static_cast<std::size_t>(page_size);
            ChildReport report{};

            const int fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                report.step = ChildStep::kOpenFailed;
                report.error = errno;
                send(report_fd, report);
                return 0;
            }

            // ACK mm/mmap.c clears VM_MAYWRITE for O_RDONLY + MAP_SHARED before the handler.
            // MAP_PRIVATE preserves it, so only sel_mmap_handle_status clears it on stock.
            void *baseline = mmap(nullptr, page, PROT_READ, MAP_PRIVATE, fd, 0);
            if (baseline == MAP_FAILED) {
                const int error = errno;
                close(fd);
                report.step = ChildStep::kBaselineMmapFailed;
                report.error = error;
                send(report_fd, report);
                return 0;
            }
            report.step = ChildStep::kBaselineMapped;
            send(report_fd, report);

            // Request 1: two pages. Stock rejects the length with EIO before remapping.
            void *mapping = mmap(nullptr, 2 * page, PROT_READ, MAP_SHARED, fd, 0);
            report.step = ChildStep::kRequest;
            report.request = static_cast<uint8_t>(StatusAbiRequest::kTwoPageShared);
            report.granted = mapping != MAP_FAILED ? 1 : 0;
            report.error = mapping != MAP_FAILED ? 0 : errno;
            if (mapping != MAP_FAILED) {
                munmap(mapping, 2 * page);
            }
            send(report_fd, report);

            // Request 2: one page at page offset 1. Stock rejects the non-zero vm_pgoff.
            mapping = mmap(nullptr, page, PROT_READ, MAP_SHARED, fd, page);
            report.request = static_cast<uint8_t>(StatusAbiRequest::kOffsetShared);
            report.granted = mapping != MAP_FAILED ? 1 : 0;
            report.error = mapping != MAP_FAILED ? 0 : errno;
            if (mapping != MAP_FAILED) {
                munmap(mapping, page);
            }
            send(report_fd, report);

            // Request 3: writable private mapping. Stock rejects VM_WRITE with EPERM.
            mapping = mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
            report.request = static_cast<uint8_t>(StatusAbiRequest::kWritablePrivate);
            report.granted = mapping != MAP_FAILED ? 1 : 0;
            report.error = mapping != MAP_FAILED ? 0 : errno;
            if (mapping != MAP_FAILED) {
                munmap(mapping, page);
            }
            send(report_fd, report);

            // Request 4: add PROT_WRITE to the baseline. Stock cleared VM_MAYWRITE in the mmap
            // handler, so mprotect fails with EACCES; a handler that keeps VM_MAYWRITE grants it.
            const int protect = mprotect(baseline, page, PROT_READ | PROT_WRITE);
            report.request = static_cast<uint8_t>(StatusAbiRequest::kMprotectWrite);
            report.granted = protect == 0 ? 1 : 0;
            report.error = protect == 0 ? 0 : errno;
            send(report_fd, report);

            munmap(baseline, page);
            close(fd);
            report.step = ChildStep::kDone;
            send(report_fd, report);
            return 0;
        }

        constexpr std::size_t kMaxReports = 8;

        std::vector<ChildReport> all_reports(const std::span<const unsigned char> bytes) {
            std::vector<ChildReport> reports;
            const std::size_t count = bytes.size() / sizeof(ChildReport);
            reports.reserve(count);
            for (std::size_t index = 0; index < count; ++index) {
                ChildReport report{};
                std::memcpy(&report, bytes.data() + index * sizeof(ChildReport), sizeof(report));
                reports.push_back(report);
            }
            return reports;
        }

        const char *request_name(const StatusAbiRequest request) {
            switch (request) {
                case StatusAbiRequest::kTwoPageShared:
                    return "TWO_PAGE_SHARED";
                case StatusAbiRequest::kOffsetShared:
                    return "OFFSET_SHARED";
                case StatusAbiRequest::kWritablePrivate:
                    return "WRITABLE_PRIVATE";
                case StatusAbiRequest::kMprotectWrite:
                    return "MPROTECT_WRITE";
            }
            return "UNKNOWN";
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

        void add_request_notes(StatusAbiProbeResult &result) {
            for (int index = 0; index < kStatusAbiRequestCount; ++index) {
                const auto request = static_cast<StatusAbiRequest>(index);
                if (result.request_error[index] < 0 && !result.granted[index]) {
                    result.notes.push_back(
                            std::string("Request ") + request_name(request) +
                            " has no reported outcome.");
                    continue;
                }
                if (result.granted[index]) {
                    result.notes.push_back(
                            std::string("Request ") + request_name(request) +
                            " was granted on the status node.");
                } else {
                    result.notes.push_back(
                            std::string("Request ") + request_name(request) + " was rejected (errno=" +
                            std::to_string(result.request_error[index]) + ").");
                }
            }
        }

        StatusAbiProbeResult settle_from_reports(const std::vector<ChildReport> &reports,
                                                 const long page_size) {
            StatusAbiProbeResult result;
            result.attempted = true;
            result.page_size = page_size;
            bool done = false;
            for (const ChildReport &report: reports) {
                switch (report.step) {
                    case ChildStep::kOpenFailed:
                        result.outcome = StatusAbiOutcome::kUnavailable;
                        result.failure_reason = "open of " + std::string(kStatusNodePath) +
                                                " failed (errno=" + std::to_string(report.error) + ").";
                        result.notes.emplace_back(
                                "Without the status node no conformance request reaches the status "
                                "handler, so nothing can be concluded about it.");
                        return result;

                    case ChildStep::kBaselineMmapFailed:
                        result.outcome = StatusAbiOutcome::kUnavailable;
                        result.failure_reason =
                                "baseline mmap of " + std::string(kStatusNodePath) +
                                " failed (errno=" + std::to_string(report.error) + ").";
                        result.notes.emplace_back(
                                "Without the baseline mapping no conformance request reaches the "
                                "status handler, so nothing can be concluded about it.");
                        return result;

                    case ChildStep::kBaselineMapped:
                        break;

                    case ChildStep::kRequest:
                        if (report.request < kStatusAbiRequestCount) {
                            result.granted[report.request] = report.granted != 0;
                            result.request_error[report.request] =
                                    report.granted != 0 ? 0 : report.error;
                        }
                        break;

                    case ChildStep::kDone:
                        done = true;
                        break;
                }
            }
            bool any_granted = false;
            for (int index = 0; index < kStatusAbiRequestCount; ++index) {
                any_granted = any_granted || result.granted[index];
            }
            add_request_notes(result);
            // One grant already proves a violation; later failure cannot invalidate that report.
            // Only a completed negative request set can establish no violation observed.
            if (any_granted) {
                result.outcome = StatusAbiOutcome::kViolation;
            } else if (done) {
                result.outcome = StatusAbiOutcome::kNoViolation;
            }
            if (any_granted) {
                result.notes.emplace_back(
                        "Stock selinuxfs rejects every request above; a grant means the status "
                        "node's mmap handler dropped the corresponding upstream check.");
            } else if (done) {
                result.notes.emplace_back(
                        "Every nonconforming request was rejected like stock selinuxfs does.");
            }
            return result;
        }

        StatusAbiProbeResult unfinished_result(const common::ChildOutcome &child,
                                                const std::vector<ChildReport> &reports,
                                                const long page_size) {
            StatusAbiProbeResult result = settle_from_reports(reports, page_size);
            result.attempted = child.end != common::ChildEnd::kNotStarted;
            // An open or baseline failure is settled, whoever ended the child: the request set was
            // never reached and the reason is already in the result.
            if (result.outcome == StatusAbiOutcome::kUnavailable) {
                return result;
            }
            const std::string run_ms = std::to_string(kChildDeadlines.run.count());
            switch (child.end) {
                case common::ChildEnd::kNotStarted:
                    result.failure_reason = "Status ABI child could not be started (errno=" +
                                            std::to_string(child.error) + "); conformance requests not sent.";
                    return result;
                case common::ChildEnd::kSetupFailed:
                    result.failure_reason = "Status ABI child could not install its seccomp trap exit.";
                    return result;
                case common::ChildEnd::kSeccompTrapped:
                    result.failure_reason = "Seccomp refused a status ABI syscall in the child.";
                    return result;
                case common::ChildEnd::kSignaled:
                    result.failure_reason = "Status ABI child was killed by " +
                                            signal_name(child.signal) +
                                            " before it finished the request set.";
                    return result;
                case common::ChildEnd::kTimedOut:
                    result.failure_reason = "Status ABI child did not finish within " + run_ms +
                                            " ms and was stopped.";
                    return result;
                case common::ChildEnd::kNotReaped:
                    result.failure_reason = "Status ABI child did not finish within " + run_ms +
                                            " ms, and was left behind because it had not died " +
                                            std::to_string(kChildDeadlines.reap.count()) +
                                            " ms after it was stopped.";
                    return result;
                case common::ChildEnd::kWaitFailed:
                    result.failure_reason = "waitpid failed (errno=" + std::to_string(child.error) +
                                            "); remaining status ABI requests are unevaluated.";
                    return result;
                case common::ChildEnd::kExited:
                    break;
            }
            result.failure_reason = "Status ABI child exited " +
                                    std::to_string(child.exit_status) +
                                    " without finishing the request set.";
            return result;
        }

        StatusAbiProbeResult probe_status_abi_at(const char *path) {
            const long page_size = sysconf(_SC_PAGESIZE);
            if (page_size <= 0) {
                StatusAbiProbeResult result;
                result.failure_reason = "Page size unavailable; status ABI probe not run.";
                return result;
            }
            std::array<unsigned char, kMaxReports * sizeof(ChildReport)> buffer{};
            const common::ChildOutcome child = common::run_disposable_child(
                    buffer,
                    kChildDeadlines,
                    [path, page_size](const int report_fd) {
                        return run_abi_requests(path, page_size, report_fd);
                    }
            );
            const std::vector<ChildReport> reports =
                    all_reports(std::span(buffer).first(child.report_length));
            const bool finished =
                    !reports.empty() && reports.back().step == ChildStep::kDone;
            if (finished) {
                return settle_from_reports(reports, page_size);
            }
            return unfinished_result(child, reports, page_size);
        }

    }  // namespace

    StatusAbiProbeResult probe_selinux_status_abi() {
        return probe_status_abi_at(kStatusNodePath);
    }

}  // namespace duckdetector::selinux
