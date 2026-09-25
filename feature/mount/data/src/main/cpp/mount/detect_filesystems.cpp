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

#include "mount/detector_core.h"
#include "mount/detector_internal.h"
#include <android/log.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/stat.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unordered_set>
#include <utility>
#include <vector>

namespace duckdetector::mount::detail {

    void detect_namespace(
            MountSnapshot &snapshot,
            std::unordered_set<std::string> &dedupe
    ) {
        bool selfReadable = false;
        const std::string selfNs = read_namespace_link("/proc/self/ns/mnt", &selfReadable);
        if (!selfReadable) {
            return;
        }

        bool initReadable = false;
        const std::string initNs = read_namespace_link("/proc/1/ns/mnt", &initReadable);
        snapshot.initNamespaceReadable = initReadable;
        if (!initReadable) {
            return;
        }

        if (selfNs != initNs) {
            add_finding(
                    snapshot,
                    dedupe,
                    "CONSISTENCY",
                    "INFO",
                    "Namespace split",
                    "Different from init",
                    "self=" + selfNs + ", init=" + initNs
            );
        } else {
            snapshot.namespaceAnomalyDetected = true;
            add_finding(
                    snapshot,
                    dedupe,
                    "CONSISTENCY",
                    "WARNING",
                    "Namespace split",
                    "Matches init",
                    "The app shares the same mount namespace as init, which is unusual for an unprivileged app."
            );
        }
    }

    void detect_filesystems(
            MountSnapshot &snapshot,
            const std::vector<MountEntry> &mounts,
            std::unordered_set<std::string> &dedupe
    ) {
        bool filesystemsReadable = false;
        const std::string filesystems = read_file_direct("/proc/filesystems", 16384,
                                                         &filesystemsReadable);
        snapshot.filesystemsReadable = filesystemsReadable;
        if (filesystemsReadable && contains_ignore_case(filesystems, "overlay")) {
            snapshot.overlayfsKernelSupport = true;
        }

        struct StatFsCheck {
            const char *path;
            const char *label;
        };
        static const std::array<StatFsCheck, 6> kChecks = {{
                                                                   {"/system", "System"},
                                                                   {"/vendor", "Vendor"},
                                                                   {"/product", "Product"},
                                                                   {"/system_ext",
                                                                    "System extension"},
                                                                   {"/odm", "ODM"},
                                                                   {"/data", "Data"},
                                                           }};

        for (const StatFsCheck &check: kChecks) {
            struct statfs st{};
            if (statfs(check.path, &st) != 0) {
                continue;
            }

            const std::string path(check.path);
            if ((path == "/system" || path == "/vendor" ||
                 path == "/product" || path == "/system_ext" ||
                 path == "/odm") &&
                static_cast<unsigned long>(st.f_type) ==
                static_cast<unsigned long>(OVERLAYFS_SUPER_MAGIC)) {
                snapshot.systemFsTypeAnomaly = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "FILESYSTEM",
                        "DANGER",
                        "System filesystem type",
                        check.path,
                        std::string(check.label) + " resolved to overlayfs."
                );
            }

            if (static_cast<unsigned long>(st.f_type) ==
                static_cast<unsigned long>(TMPFS_MAGIC) &&
                (path == "/system" || path == "/vendor")) {
                snapshot.tmpfsSizeAnomaly = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "FILESYSTEM",
                        "WARNING",
                        "System tmpfs",
                        check.path,
                        std::string(check.label) +
                        " resolved to tmpfs, which is unusual for stock partitions."
                );
            }
        }

        for (const MountEntry &entry: mounts) {
            if (lowercase_copy(entry.fsType) == "tmpfs" && entry.target == "/sbin") {
                snapshot.tmpfsSizeAnomaly = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "FILESYSTEM",
                        "WARNING",
                        "Tmpfs mount",
                        entry.target,
                        entry.options
                );
            }
        }
    }

    void detect_inconsistent_mount(
            MountSnapshot &snapshot,
            const std::vector<MountEntry> &mounts,
            std::unordered_set<std::string> &dedupe
    ) {
        std::array<char, PATH_MAX> resolved{};
        const ssize_t resolvedLength = syscall_readlink_path("/proc/self/exe", resolved.data(),
                                                             resolved.size() - 1);
        if (resolvedLength <= 0) {
            return;
        }
        resolved[static_cast<size_t>(resolvedLength)] = '\0';

        struct statfs directFs{};
        struct statfs resolvedFs{};
        if (statfs("/proc/self/exe", &directFs) != 0 ||
            statfs(resolved.data(), &resolvedFs) != 0) {
            return;
        }

        if (directFs.f_type != resolvedFs.f_type) {
            snapshot.inconsistentMountDetected = true;
            add_finding(
                    snapshot,
                    dedupe,
                    "CONSISTENCY",
                    "DANGER",
                    "Mount consistency",
                    "Filesystem mismatch",
                    "direct=0x" + std::to_string(static_cast<unsigned long>(directFs.f_type)) +
                    ", resolved=0x" +
                    std::to_string(static_cast<unsigned long>(resolvedFs.f_type))
            );
            return;
        }

        if (static_cast<unsigned long>(directFs.f_type) ==
            static_cast<unsigned long>(OVERLAYFS_SUPER_MAGIC)) {
            const bool hasSystemOverlay = std::any_of(
                    mounts.begin(),
                    mounts.end(),
                    [](const MountEntry &entry) {
                        return (entry.target == "/system" || entry.target == "/system/bin") &&
                               (entry.fsType == "overlay" || entry.fsType == "overlayfs");
                    }
            );
            if (!hasSystemOverlay) {
                snapshot.inconsistentMountDetected = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "CONSISTENCY",
                        "DANGER",
                        "Mount consistency",
                        "Hidden overlayfs",
                        "statfs reported overlayfs for /proc/self/exe, but mount tables did not show a matching system overlay."
                );
            }
        }
    }

}  // namespace duckdetector::mount::detail
