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

    int syscall_open_readonly(const char *path, int flags) {
        return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, flags));
    }

    ssize_t syscall_read_fd(int fd, void *buffer, size_t count) {
        return syscall(__NR_read, fd, buffer, count);
    }

    int syscall_close_fd(int fd) {
        return static_cast<int>(syscall(__NR_close, fd));
    }

    int syscall_stat_path(const char *path, struct stat *st) {
#if defined(__aarch64__) || defined(__x86_64__)
        return static_cast<int>(syscall(__NR_newfstatat, AT_FDCWD, path, st, 0));
#elif defined(__arm__) || defined(__i386__)
        return static_cast<int>(syscall(__NR_fstatat64, AT_FDCWD, path, st, 0));
#else
        return stat(path, st);
#endif
    }

    ssize_t syscall_readlink_path(const char *path, char *buffer, size_t bufferSize) {
        return syscall(__NR_readlinkat, AT_FDCWD, path, buffer, bufferSize);
    }

    std::string trim_copy(std::string value) {
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
            value.erase(value.begin());
        }
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
            value.pop_back();
        }
        return value;
    }

    std::string lowercase_copy(std::string value) {
        std::transform(
                value.begin(),
                value.end(),
                value.begin(),
                [](unsigned char ch) {
                    return static_cast<char>(std::tolower(ch));
                }
        );
        return value;
    }

    std::string sanitize_field(std::string value) {
        for (char &ch: value) {
            if (ch == '\n' || ch == '\r' || ch == '\t') {
                ch = ' ';
            }
        }
        return trim_copy(value);
    }

    bool contains_ignore_case(const std::string &haystack, const std::string &needle) {
        return lowercase_copy(haystack).find(lowercase_copy(needle)) != std::string::npos;
    }

    std::string read_file_direct(const char *path, size_t maxSize, bool *readable) {
        if (readable != nullptr) {
            *readable = false;
        }

        const int fd = syscall_open_readonly(path);
        if (fd < 0) {
            return "";
        }

        std::string content;
        content.resize(maxSize);
        const ssize_t bytesRead = syscall_read_fd(fd, content.data(), maxSize - 1);
        syscall_close_fd(fd);

        if (bytesRead <= 0) {
            return "";
        }

        content.resize(static_cast<size_t>(bytesRead));
        if (readable != nullptr) {
            *readable = true;
        }
        return content;
    }

    std::string read_namespace_link(const char *path, bool *readable) {
        if (readable != nullptr) {
            *readable = false;
        }

        std::array<char, 256> buffer{};
        const ssize_t length = syscall_readlink_path(path, buffer.data(), buffer.size() - 1);
        if (length <= 0) {
            return "";
        }
        buffer[static_cast<size_t>(length)] = '\0';
        if (readable != nullptr) {
            *readable = true;
        }
        return std::string(buffer.data());
    }

    AccessResult check_access(
            const char *path,
            bool expectDirectory,
            MountSnapshot &snapshot
    ) {
        snapshot.permissionTotal += 1;

        struct stat st{};
        if (syscall_stat_path(path, &st) == 0) {
            snapshot.permissionAccessible += 1;
            if (expectDirectory && !S_ISDIR(st.st_mode)) {
                return AccessResult::NotExists;
            }
            return AccessResult::Exists;
        }

        if (errno == EACCES || errno == EPERM) {
            snapshot.permissionDenied += 1;
            return AccessResult::PermissionDenied;
        }

        snapshot.permissionAccessible += 1;
        return AccessResult::NotExists;
    }

    std::vector<MountEntry> parse_mounts(const std::string &raw) {
        std::vector<MountEntry> entries;
        std::istringstream stream(raw);
        std::string line;
        while (std::getline(stream, line)) {
            MountEntry entry;
            std::istringstream lineStream(line);
            if (!(lineStream >> entry.source >> entry.target >> entry.fsType
                             >> entry.options)) {
                continue;
            }
            entries.push_back(entry);
        }
        return entries;
    }

    bool parse_mount_info_line(const std::string &line, MountInfoEntry &entry) {
        const size_t separator = line.find(" - ");
        if (separator == std::string::npos) {
            return false;
        }

        std::istringstream left(line.substr(0, separator));
        std::string majorMinor;
        if (!(left >> entry.id >> entry.parentId >> majorMinor >> entry.root >> entry.target
                   >> entry.options)) {
            return false;
        }
        if (std::sscanf(majorMinor.c_str(), "%u:%u", &entry.major, &entry.minor) != 2) {
            return false;
        }

        std::string optional;
        while (left >> optional) {
            entry.optionalFields.push_back(optional);
        }

        std::istringstream right(line.substr(separator + 3));
        if (!(right >> entry.fsType >> entry.source)) {
            return false;
        }
        std::getline(right, entry.superOptions);
        entry.superOptions = trim_copy(entry.superOptions);
        return true;
    }

    std::vector<MountInfoEntry> parse_mount_info(const std::string &raw) {
        std::vector<MountInfoEntry> entries;
        std::istringstream stream(raw);
        std::string line;
        while (std::getline(stream, line)) {
            MountInfoEntry entry;
            if (parse_mount_info_line(line, entry)) {
                entries.push_back(entry);
            }
        }
        std::sort(
                entries.begin(),
                entries.end(),
                [](const MountInfoEntry &left, const MountInfoEntry &right) {
                    return left.id < right.id;
                }
        );
        return entries;
    }

    void add_finding(
            MountSnapshot &snapshot,
            std::unordered_set<std::string> &dedupe,
            const std::string &group,
            const std::string &severity,
            const std::string &label,
            const std::string &value,
            const std::string &detail
    ) {
        const std::string key = group + "|" + label + "|" + value + "|" + detail;
        if (!dedupe.insert(key).second) {
            return;
        }
        snapshot.findings.push_back(
                MountFindingRecord{
                        group,
                        severity,
                        sanitize_field(label),
                        sanitize_field(value),
                        sanitize_field(detail),
                }
        );
    }

    bool is_system_partition(const std::string &path) {
        static const std::array<const char *, 6> kPaths = {
                "/system",
                "/system_root",
                "/vendor",
                "/product",
                "/system_ext",
                "/odm",
        };
        return std::find(kPaths.begin(), kPaths.end(), path) != kPaths.end();
    }

    bool starts_with(const std::string &value, const std::string &prefix) {
        return value.rfind(prefix, 0) == 0;
    }

    std::string join_optional_fields(const std::vector<std::string> &fields) {
        std::string joined;
        for (size_t index = 0; index < fields.size(); ++index) {
            joined += fields[index];
            if (index + 1 < fields.size()) {
                joined += " ";
            }
        }
        return joined;
    }

}  // namespace duckdetector::mount::detail
