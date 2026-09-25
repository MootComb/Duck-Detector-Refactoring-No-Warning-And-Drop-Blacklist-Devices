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

    void detect_mounts(
            MountSnapshot &snapshot,
            const std::vector<MountEntry> &mounts,
            std::unordered_set<std::string> &dedupe
    ) {
        snapshot.mountsReadable = !mounts.empty();
        snapshot.mountEntryCount = static_cast<int>(mounts.size());

        for (const MountEntry &entry: mounts) {
            const std::string lowerSource = lowercase_copy(entry.source);
            const std::string lowerTarget = lowercase_copy(entry.target);
            const std::string lowerFs = lowercase_copy(entry.fsType);
            const std::string lowerOptions = lowercase_copy(entry.options);

            if (lowerSource.find(".magisk") != std::string::npos ||
                lowerTarget.find(".magisk") != std::string::npos ||
                lowerTarget.find("/data/adb/modules") != std::string::npos ||
                lowerSource.find("magisk/mirror") != std::string::npos) {
                snapshot.magiskMountDetected = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "ARTIFACTS",
                        "DANGER",
                        "Magisk mounts",
                        entry.target,
                        entry.source + " -> " + entry.target + " (" + entry.fsType + ")"
                );
            }

            if (is_system_partition(entry.target)) {
                const bool isRw = starts_with(lowerOptions, "rw,") || lowerOptions == "rw";
                if (isRw) {
                    snapshot.systemRwDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "RUNTIME",
                            "DANGER",
                            "System RW",
                            entry.target,
                            "Mount options: " + entry.options
                    );
                }

                if ((lowerFs == "overlay" || lowerFs == "overlayfs") &&
                    lowerTarget.find("/overlay/") == std::string::npos) {
                    snapshot.overlayMountDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "RUNTIME",
                            "DANGER",
                            "Overlay mount",
                            entry.target,
                            entry.source + " -> " + entry.target + " (" + entry.fsType + ")"
                    );
                }

                if (lowerSource.find("/dev/block/loop") != std::string::npos ||
                    lowerSource.find("modules.img") != std::string::npos ||
                    lowerSource.find("overlayfs_loop") != std::string::npos) {
                    snapshot.loopDeviceDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "RUNTIME",
                            "DANGER",
                            "Loop device mount",
                            entry.target,
                            entry.source + " -> " + entry.target
                    );
                }

                if (lowerSource.find("/dev/mapper/") == std::string::npos &&
                    lowerSource.find("/dev/block/dm-") == std::string::npos &&
                    lowerFs != "overlay" &&
                    lowerFs != "overlayfs") {
                    snapshot.dmVerityBypassDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "RUNTIME",
                            "WARNING",
                            "Direct block mount",
                            entry.target,
                            "Expected dm-verity mapper source, got " + entry.source
                    );
                }
            }

            if (lowerFs == "tmpfs" &&
                (lowerTarget == "/sbin" || lowerTarget == "/.magisk" ||
                 lowerTarget == "/patch_hw" || lowerTarget == "/dev/meta_hybird_mnt")) {
                snapshot.suspiciousTmpfsDetected = true;
                snapshot.tmpfsSizeAnomaly = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "FILESYSTEM",
                        "WARNING",
                        "Suspicious tmpfs",
                        entry.target,
                        entry.source + " -> " + entry.target + " (" + entry.options + ")"
                );
            }

            if (lowerSource.find("ksu") != std::string::npos ||
                lowerSource.find("kernelsu") != std::string::npos ||
                lowerSource.find("magic_mount") != std::string::npos ||
                lowerOptions.find("workdir=/data/adb") != std::string::npos) {
                snapshot.ksuOverlayDetected = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "ARTIFACTS",
                        "DANGER",
                        "KernelSU or magic-mount overlay",
                        entry.target,
                        entry.source + " -> " + entry.target
                );
            }

            if (lowerSource.find("meta-hybrid") != std::string::npos ||
                lowerSource.find("meta_hybird") != std::string::npos ||
                lowerSource.find("magic_mount") != std::string::npos ||
                lowerTarget.find(".magic_mount") != std::string::npos) {
                snapshot.metaHybridMountDetected = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "ARTIFACTS",
                        "DANGER",
                        "Meta-Hybrid or magic mount",
                        entry.target,
                        entry.source + " -> " + entry.target
                );
            }
        }
    }

    void detect_mountinfo(
            MountSnapshot &snapshot,
            const std::vector<MountInfoEntry> &entries,
            std::unordered_set<std::string> &dedupe
    ) {
        snapshot.mountInfoReadable = !entries.empty();
        snapshot.mountInfoEntryCount = static_cast<int>(entries.size());

        int dataDataMountId = -1;

        for (size_t index = 0; index < entries.size(); ++index) {
            const MountInfoEntry &entry = entries[index];
            const std::string optionalJoined = join_optional_fields(entry.optionalFields);
            const std::string lowerOptional = lowercase_copy(optionalJoined);
            const std::string lowerSuper = lowercase_copy(entry.superOptions);

            if (entry.target == "/data/data") {
                dataDataMountId = entry.id;
            }

            if (is_system_partition(entry.target) && entry.root != "/") {
                snapshot.bindMountDetected = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "CONSISTENCY",
                        "DANGER",
                        "Bind mount root",
                        entry.target,
                        "root=" + entry.root + ", source=" + entry.source
                );
            }

            if (is_system_partition(entry.target) &&
                (lowerSuper.find("context=") != std::string::npos ||
                 lowerSuper.find("fscontext=") != std::string::npos ||
                 lowerSuper.find("defcontext=") != std::string::npos ||
                 lowerSuper.find("rootcontext=") != std::string::npos)) {
                snapshot.mountOptionsAnomaly = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "CONSISTENCY",
                        "DANGER",
                        "SELinux mount override",
                        entry.target,
                        entry.superOptions
                );
            }

            if (entry.target == "/" && lowerOptional.find("shared:") == std::string::npos &&
                lowerOptional.find("master:") == std::string::npos &&
                lowerOptional.find("unbindable") == std::string::npos) {
                snapshot.mountPropagationAnomaly = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "CONSISTENCY",
                        "WARNING",
                        "Root mount propagation",
                        "Private",
                        optionalJoined.empty()
                        ? "No shared/master propagation markers were present on the root mount."
                        : optionalJoined
                );
            }

            if (entry.target == "/apex/com.android.art" && index + 1 < entries.size() &&
                entries[index + 1].id > entry.id + 1) {
                snapshot.mountIdLoopholeDetected = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "CONSISTENCY",
                        "DANGER",
                        "Mount ID loophole",
                        "Gap after ART",
                        "Expected next ID " + std::to_string(entry.id + 1) + ", got " +
                        std::to_string(entries[index + 1].id)
                );
            }

            if (entry.target == "/data_mirror" && index > 0) {
                const MountInfoEntry &previous = entries[index - 1];
                if (previous.id + 1 != entry.id &&
                    previous.target.find("/data/user") == std::string::npos) {
                    snapshot.mountIdLoopholeDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "CONSISTENCY",
                            "DANGER",
                            "Mount ID loophole",
                            "Gap before /data_mirror",
                            "Previous mount " + previous.target + " has ID " +
                            std::to_string(previous.id)
                    );
                }
            }
        }

#ifdef __NR_statx
        snapshot.statxSupported = is_statx_supported();

        if (snapshot.statxSupported && dataDataMountId > 0) {
            struct statx stx{};
            const int statxResult = static_cast<int>(
                    syscall(__NR_statx, AT_FDCWD, "/data/data", AT_NO_AUTOMOUNT,
                            STATX_BASIC_STATS | kStatxMountIdMask, &stx)
            );
            if (statxResult == 0 && (stx.stx_mask & kStatxMountIdMask) != 0 &&
                stx.stx_mnt_id != static_cast<std::uint64_t>(dataDataMountId)) {
                snapshot.statxMntIdMismatch = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "CONSISTENCY",
                        "DANGER",
                        "statx mount ID mismatch",
                        "/data/data",
                        "mountinfo=" + std::to_string(dataDataMountId) + ", statx=" +
                        std::to_string(static_cast<unsigned long long>(stx.stx_mnt_id))
                );
            }
        }

        struct StatxCheck {
            const char *path;
            const char *label;
        };
        static const std::array<StatxCheck, 3> kChecks = {{
                                                                  {"/system/bin", "System bin"},
                                                                  {"/system/lib64",
                                                                   "System lib64"},
                                                                  {"/vendor/bin", "Vendor bin"},
                                                          }};

        std::map<std::string, int> mountIds;
        for (const MountInfoEntry &entry: entries) {
            mountIds[entry.target] = entry.id;
        }

        if (snapshot.statxSupported) {
            for (const StatxCheck &check: kChecks) {
                struct statx stx{};
                const int statxResult = static_cast<int>(
                        syscall(__NR_statx, AT_FDCWD, check.path, AT_NO_AUTOMOUNT,
                                STATX_BASIC_STATS | kStatxMountIdMask, &stx)
                );
                if (statxResult != 0 || (stx.stx_mask & kStatxMountIdMask) == 0) {
                    continue;
                }

                const bool mountRootFlagKnown =
                        (stx.stx_attributes_mask & kStatxMountRootMask) != 0;
                const bool isMountRoot =
                        mountRootFlagKnown && (stx.stx_attributes & kStatxMountRootMask) != 0;
                if (isMountRoot) {
                    snapshot.statxMountRootAnomaly = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "CONSISTENCY",
                            "WARNING",
                            "statx mount root",
                            check.path,
                            std::string(check.label) +
                            " unexpectedly reports mount-root attributes."
                    );
                }

                const auto mountIdIt = mountIds.find(check.path);
                if (mountIdIt != mountIds.end() &&
                    static_cast<unsigned long long>(stx.stx_mnt_id) !=
                    static_cast<unsigned long long>(mountIdIt->second)) {
                    snapshot.statxMountRootAnomaly = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "CONSISTENCY",
                            "DANGER",
                            "statx mount cross-check",
                            check.path,
                            "mountinfo=" + std::to_string(mountIdIt->second) + ", statx=" +
                            std::to_string(static_cast<unsigned long long>(stx.stx_mnt_id))
                    );
                }
            }
        }
#else
        snapshot.statxSupported = false;
#endif
    }

}  // namespace duckdetector::mount::detail
