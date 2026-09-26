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

#include "virtualization/honeypot_traps.h"
#include "virtualization/honeypot_traps_internal.h"
#include "common/payload_codec.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <math.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <algorithm>
#include <cstdint>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace duckdetector::virtualization {

    using namespace detail;

    std::string run_sacrificial_syscall_pack() {
#if defined(__aarch64__)
        if (g_sacrificialSyscallPackDisabled) {
            return encode_basic_pack(
                    true,
                    false,
                    true,
                    "Sacrificial syscall pack was disabled after a previous SIGSYS in this helper process."
            );
        }

        int pipefd[2] = {-1, -1};
        if (pipe(pipefd) != 0) {
            return encode_basic_pack(true, false, false, "Failed to create pipe for sacrificial syscall pack.");
        }

        const pid_t child = fork();
        if (child < 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            return encode_basic_pack(true, false, false, "Failed to fork sacrificial syscall child.");
        }

        if (child == 0) {
            close(pipefd[0]);

            auto call_via_syscall = [](long number,
                                       long arg0,
                                       long arg1,
                                       long arg2,
                                       long arg3,
                                       long arg4,
                                       long arg5,
                                       int *outErrno) -> long {
                errno = 0;
                const long ret = syscall(number, arg0, arg1, arg2, arg3, arg4, arg5);
                if (outErrno != nullptr) {
                    *outErrno = errno;
                }
                return ret;
            };

            std::vector<SyscallItemAccumulator> items;
            items.reserve(5);

            SyscallItemAccumulator openat2Item;
            const bool openat2Supported = run_syscall_item("openat2", [&](int attempt) {
                const std::string path = "/proc/self/virtualization_openat2_missing_" + std::to_string(attempt);
                struct open_how how{};
                how.flags = static_cast<std::uint64_t>(O_RDONLY | O_CLOEXEC);
                SyscallAttemptTriplet triplet;
                const long long wrapperStart = monotonic_ns();
                triplet.wrapperRet = call_via_syscall(
                        __NR_openat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        reinterpret_cast<long>(&how),
                        sizeof(how),
                        0,
                        0,
                        &triplet.wrapperErrno
                );
                triplet.wrapperElapsedNs = monotonic_ns() - wrapperStart;
                const long long wrapperRepeatStart = monotonic_ns();
                triplet.wrapperRepeatRet = call_via_syscall(
                        __NR_openat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        reinterpret_cast<long>(&how),
                        sizeof(how),
                        0,
                        0,
                        &triplet.wrapperRepeatErrno
                );
                triplet.wrapperRepeatElapsedNs = monotonic_ns() - wrapperRepeatStart;
                const long long asmStart = monotonic_ns();
                triplet.asmRet = asm_syscall6(
                        __NR_openat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        reinterpret_cast<long>(&how),
                        sizeof(how),
                        0,
                        0,
                        &triplet.asmErrno
                );
                triplet.asmElapsedNs = monotonic_ns() - asmStart;
                return triplet;
            }, &openat2Item);

            SyscallItemAccumulator statxItem;
            const bool statxSupported = run_syscall_item("statx", [&](int attempt) {
                const std::string path = "/proc/self/virtualization_statx_missing_" + std::to_string(attempt);
                struct statx statxBuffer{};
                SyscallAttemptTriplet triplet;
                const long long wrapperStart = monotonic_ns();
                triplet.wrapperRet = call_via_syscall(
                        __NR_statx,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        0,
                        STATX_BASIC_STATS,
                        reinterpret_cast<long>(&statxBuffer),
                        0,
                        &triplet.wrapperErrno
                );
                triplet.wrapperElapsedNs = monotonic_ns() - wrapperStart;
                const long long wrapperRepeatStart = monotonic_ns();
                triplet.wrapperRepeatRet = call_via_syscall(
                        __NR_statx,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        0,
                        STATX_BASIC_STATS,
                        reinterpret_cast<long>(&statxBuffer),
                        0,
                        &triplet.wrapperRepeatErrno
                );
                triplet.wrapperRepeatElapsedNs = monotonic_ns() - wrapperRepeatStart;
                const long long asmStart = monotonic_ns();
                triplet.asmRet = asm_syscall6(
                        __NR_statx,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        0,
                        STATX_BASIC_STATS,
                        reinterpret_cast<long>(&statxBuffer),
                        0,
                        &triplet.asmErrno
                );
                triplet.asmElapsedNs = monotonic_ns() - asmStart;
                return triplet;
            }, &statxItem);

            SyscallItemAccumulator memfdItem;
            const bool memfdSupported = run_syscall_item("memfd_create", [&](int attempt) {
                const std::string name = "virt_memfd_" + std::to_string(attempt);
                SyscallAttemptTriplet triplet;
                const long long wrapperStart = monotonic_ns();
                triplet.wrapperRet = call_via_syscall(
                        __NR_memfd_create,
                        reinterpret_cast<long>(name.c_str()),
                        MFD_CLOEXEC,
                        0,
                        0,
                        0,
                        0,
                        &triplet.wrapperErrno
                );
                triplet.wrapperElapsedNs = monotonic_ns() - wrapperStart;
                if (triplet.wrapperRet >= 0) close(static_cast<int>(triplet.wrapperRet));
                const long long wrapperRepeatStart = monotonic_ns();
                triplet.wrapperRepeatRet = call_via_syscall(
                        __NR_memfd_create,
                        reinterpret_cast<long>(name.c_str()),
                        MFD_CLOEXEC,
                        0,
                        0,
                        0,
                        0,
                        &triplet.wrapperRepeatErrno
                );
                triplet.wrapperRepeatElapsedNs = monotonic_ns() - wrapperRepeatStart;
                if (triplet.wrapperRepeatRet >= 0) close(static_cast<int>(triplet.wrapperRepeatRet));
                const long long asmStart = monotonic_ns();
                triplet.asmRet = asm_syscall6(
                        __NR_memfd_create,
                        reinterpret_cast<long>(name.c_str()),
                        MFD_CLOEXEC,
                        0,
                        0,
                        0,
                        0,
                        &triplet.asmErrno
                );
                triplet.asmElapsedNs = monotonic_ns() - asmStart;
                if (triplet.asmRet >= 0) close(static_cast<int>(triplet.asmRet));
                return triplet;
            }, &memfdItem);

            SyscallItemAccumulator pidfdItem;
            const bool pidfdSupported = run_syscall_item("pidfd_open", [&](int) {
                SyscallAttemptTriplet triplet;
                const pid_t pid = getpid();
                const long long wrapperStart = monotonic_ns();
                triplet.wrapperRet = call_via_syscall(
                        __NR_pidfd_open,
                        pid,
                        0,
                        0,
                        0,
                        0,
                        0,
                        &triplet.wrapperErrno
                );
                triplet.wrapperElapsedNs = monotonic_ns() - wrapperStart;
                if (triplet.wrapperRet >= 0) close(static_cast<int>(triplet.wrapperRet));
                const long long wrapperRepeatStart = monotonic_ns();
                triplet.wrapperRepeatRet = call_via_syscall(
                        __NR_pidfd_open,
                        pid,
                        0,
                        0,
                        0,
                        0,
                        0,
                        &triplet.wrapperRepeatErrno
                );
                triplet.wrapperRepeatElapsedNs = monotonic_ns() - wrapperRepeatStart;
                if (triplet.wrapperRepeatRet >= 0) close(static_cast<int>(triplet.wrapperRepeatRet));
                const long long asmStart = monotonic_ns();
                triplet.asmRet = asm_syscall6(
                        __NR_pidfd_open,
                        pid,
                        0,
                        0,
                        0,
                        0,
                        0,
                        &triplet.asmErrno
                );
                triplet.asmElapsedNs = monotonic_ns() - asmStart;
                if (triplet.asmRet >= 0) close(static_cast<int>(triplet.asmRet));
                return triplet;
            }, &pidfdItem);

            SyscallItemAccumulator renameat2Item;
            const bool renameat2Supported = run_syscall_item("renameat2", [&](int attempt) {
                const std::string oldPath = "/proc/self/virtualization_renameat2_old_" + std::to_string(attempt);
                const std::string newPath = "/proc/self/virtualization_renameat2_new_" + std::to_string(attempt);
                SyscallAttemptTriplet triplet;
                const long long wrapperStart = monotonic_ns();
                triplet.wrapperRet = call_via_syscall(
                        __NR_renameat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(oldPath.c_str()),
                        AT_FDCWD,
                        reinterpret_cast<long>(newPath.c_str()),
                        0,
                        0,
                        &triplet.wrapperErrno
                );
                triplet.wrapperElapsedNs = monotonic_ns() - wrapperStart;
                const long long wrapperRepeatStart = monotonic_ns();
                triplet.wrapperRepeatRet = call_via_syscall(
                        __NR_renameat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(oldPath.c_str()),
                        AT_FDCWD,
                        reinterpret_cast<long>(newPath.c_str()),
                        0,
                        0,
                        &triplet.wrapperRepeatErrno
                );
                triplet.wrapperRepeatElapsedNs = monotonic_ns() - wrapperRepeatStart;
                const long long asmStart = monotonic_ns();
                triplet.asmRet = asm_syscall6(
                        __NR_renameat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(oldPath.c_str()),
                        AT_FDCWD,
                        reinterpret_cast<long>(newPath.c_str()),
                        0,
                        0,
                        &triplet.asmErrno
                );
                triplet.asmElapsedNs = monotonic_ns() - asmStart;
                return triplet;
            }, &renameat2Item);

            if (!(openat2Supported && statxSupported && memfdSupported && pidfdSupported && renameat2Supported)) {
                const std::string payload = encode_basic_pack(
                        true,
                        false,
                        false,
                        "Sacrificial syscall pack is unsupported on this kernel, ABI, or libc surface."
                );
                write(pipefd[1], payload.data(), payload.size());
                close(pipefd[1]);
                _exit(0);
            }

            items.push_back(openat2Item);
            items.push_back(statxItem);
            items.push_back(memfdItem);
            items.push_back(pidfdItem);
            items.push_back(renameat2Item);

            std::ostringstream payload;
            payload << "AVAILABLE=1\nSUPPORTED=1\nDISABLED=0\nDETAIL="
                    << encode_value("Executed the syscall pack in a sacrificial child process.") << '\n';
            for (const auto &item: items) {
                payload << encode_sacrificial_item(item);
            }
            const std::string serialized = payload.str();
            write(pipefd[1], serialized.data(), serialized.size());
            close(pipefd[1]);
            _exit(0);
        }

        close(pipefd[1]);
        int status = 0;
        waitpid(child, &status, 0);
        std::string payload;
        char buffer[1024];
        ssize_t read = 0;
        while ((read = ::read(pipefd[0], buffer, sizeof(buffer))) > 0) {
            payload.append(buffer, static_cast<std::size_t>(read));
        }
        close(pipefd[0]);

        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
            g_sacrificialSyscallPackDisabled = true;
            return encode_basic_pack(
                    true,
                    false,
                    true,
                    "Sacrificial syscall child died with SIGSYS. The helper process will not run this pack again."
            );
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || payload.empty()) {
            return encode_basic_pack(
                    true,
                    false,
                    false,
                    "Sacrificial syscall child did not return a valid result."
            );
        }
        return payload;
#else
        return encode_basic_pack(
                true,
                false,
                false,
                "Sacrificial syscall pack is only supported on arm64-v8a."
        );
#endif
    }

}  // namespace duckdetector::virtualization
