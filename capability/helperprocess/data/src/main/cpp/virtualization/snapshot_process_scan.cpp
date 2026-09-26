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

#include "virtualization/snapshot_scan.h"

#include <dirent.h>
#include <limits.h>
#include <unistd.h>

#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace duckdetector::virtualization {

    namespace {

        std::string read_link_target(const char *path) {
            char buffer[PATH_MAX] = {0};
            const ssize_t read = readlink(path, buffer, sizeof(buffer) - 1);
            if (read <= 0) {
                return "";
            }
            return std::string(buffer, static_cast<std::size_t>(read));
        }

        std::string mount_anchor_key(
                const std::string &mount_id,
                const std::string &major_minor,
                const std::string &root,
                const std::string &mount_point,
                const std::string &fs_type,
                const std::string &source
        ) {
            return mount_id + "|" + major_minor + "|" + root + "|" + mount_point + "|" +
                   fs_type + "|" + source;
        }

    }  // namespace

    namespace snapshot_scan {

        void scan_maps(Snapshot &snapshot, std::set<std::string> &dedupe) {
            std::ifstream input("/proc/self/maps");
            if (!input.is_open()) {
                return;
            }

            const std::vector<std::string> translation_tokens = {
                    "libhoudini.so",
                    "libnb.so",
                    "libndk_translation.so",
            };
            std::set<std::string> avf_tokens;
            std::string line;
            while (std::getline(input, line)) {
                snapshot.mapLineCount += 1;

                for (const auto &token: translation_tokens) {
                    if (line.find(token) != std::string::npos) {
                        add_finding(
                                snapshot,
                                dedupe,
                                SnapshotGroup::kTranslation,
                                "WARNING",
                                "Mapped translation library",
                                token,
                                line
                        );
                    }
                }

                if (line.find("goldfish") != std::string::npos ||
                    line.find("ranchu") != std::string::npos ||
                    line.find("qemu") != std::string::npos) {
                    add_finding(
                            snapshot,
                            dedupe,
                            SnapshotGroup::kRuntime,
                            "DANGER",
                            "Mapped emulator library",
                            "Present",
                            line
                    );
                }

                if (line.find("authfs") != std::string::npos) avf_tokens.insert("authfs");
                if (line.find("virtiofs") != std::string::npos) avf_tokens.insert("virtiofs");
                if (line.find("crosvm") != std::string::npos) avf_tokens.insert("crosvm");
                if (line.find("microdroid") != std::string::npos) avf_tokens.insert("microdroid");
            }

            if (avf_tokens.size() >= 2) {
                std::ostringstream joined;
                bool first = true;
                for (const auto &token: avf_tokens) {
                    if (!first) joined << ", ";
                    joined << token;
                    first = false;
                }
                add_finding(
                        snapshot,
                        dedupe,
                        SnapshotGroup::kRuntime,
                        "DANGER",
                        "AVF runtime",
                        joined.str(),
                        "Multiple AVF or Microdroid runtime tokens were visible from /proc/self/maps.",
                        EarlySignal::kAvfRuntime
                );
            }
        }

        void scan_mountinfo(Snapshot &snapshot, std::set<std::string> &dedupe) {
            std::ifstream input("/proc/self/mountinfo");
            if (!input.is_open()) {
                return;
            }

            bool authfs_seen = false;
            bool avf_other_seen = false;
            std::string line;
            while (std::getline(input, line)) {
                snapshot.mountInfoCount += 1;
                if (line.find("authfs") != std::string::npos) {
                    authfs_seen = true;
                }
                if (line.find("virtiofs") != std::string::npos ||
                    line.find("microdroid") != std::string::npos ||
                    line.find("crosvm") != std::string::npos) {
                    avf_other_seen = true;
                }

                const auto separator = line.find(" - ");
                if (separator == std::string::npos) {
                    continue;
                }
                std::istringstream left(line.substr(0, separator));
                std::istringstream right(line.substr(separator + 3));
                std::string mount_id;
                std::string parent_id;
                std::string major_minor;
                std::string root;
                std::string mount_point;
                if (!(left >> mount_id >> parent_id >> major_minor >> root >> mount_point)) {
                    continue;
                }

                std::string fs_type;
                std::string source;
                if (!(right >> fs_type >> source)) {
                    continue;
                }

                const std::string anchor_key = mount_anchor_key(
                        mount_id,
                        major_minor,
                        root,
                        mount_point,
                        fs_type,
                        source
                );
                if (mount_point == "/apex") snapshot.apexMountKey = anchor_key;
                if (mount_point == "/system") snapshot.systemMountKey = anchor_key;
                if (mount_point == "/vendor") snapshot.vendorMountKey = anchor_key;

                if ((mount_point == "/apex" || mount_point == "/system" ||
                     mount_point == "/vendor") &&
                    contains_token(fs_type + " " + source,
                                   {"authfs", "virtiofs", "microdroid", "crosvm"})) {
                    add_finding(
                            snapshot,
                            dedupe,
                            SnapshotGroup::kRuntime,
                            "DANGER",
                            "Mount anchor artifact",
                            mount_point,
                            anchor_key
                    );
                }
            }

            if (authfs_seen) {
                add_finding(
                        snapshot,
                        dedupe,
                        SnapshotGroup::kRuntime,
                        "DANGER",
                        "authfs runtime",
                        "Present",
                        "authfs mount was visible from /proc/self/mountinfo.",
                        EarlySignal::kAuthfsRuntime
                );
            }
            if (authfs_seen && avf_other_seen) {
                add_finding(
                        snapshot,
                        dedupe,
                        SnapshotGroup::kRuntime,
                        "DANGER",
                        "AVF runtime",
                        "Present",
                        "Mount table contains authfs together with additional AVF or Microdroid tokens.",
                        EarlySignal::kAvfRuntime
                );
            }
        }

        void scan_mount_namespace(Snapshot &snapshot) {
            snapshot.mountNamespaceInode = read_link_target("/proc/self/ns/mnt");
        }

        void scan_fd_targets(Snapshot &snapshot, std::set<std::string> &dedupe) {
            DIR *dir = opendir("/proc/self/fd");
            if (dir == nullptr) {
                return;
            }

            std::vector<std::string> translation_tokens = {
                    "libhoudini.so",
                    "libnb.so",
                    "libndk_translation.so",
            };

            struct dirent *entry = nullptr;
            while ((entry = readdir(dir)) != nullptr) {
                if (entry->d_name[0] == '.') {
                    continue;
                }
                snapshot.fdCount += 1;
                const std::string path = std::string("/proc/self/fd/") + entry->d_name;
                char buffer[PATH_MAX] = {0};
                const ssize_t read = readlink(path.c_str(), buffer, sizeof(buffer) - 1);
                if (read <= 0) {
                    continue;
                }
                std::string target(buffer, static_cast<std::size_t>(read));

                for (const auto &token: translation_tokens) {
                    if (target.find(token) != std::string::npos) {
                        add_finding(
                                snapshot,
                                dedupe,
                                SnapshotGroup::kTranslation,
                                "WARNING",
                                "FD target translation residue",
                                token,
                                target
                        );
                    }
                }

                if (contains_token(target, {"qemu", "goldfish", "ranchu", "authfs", "crosvm",
                                            "microdroid"})) {
                    add_finding(
                            snapshot,
                            dedupe,
                            SnapshotGroup::kRuntime,
                            "DANGER",
                            "FD target runtime artifact",
                            "Present",
                            target
                    );
                }
            }
            closedir(dir);
        }

    }  // namespace snapshot_scan

}  // namespace duckdetector::virtualization
