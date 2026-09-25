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

#include "customrom/property_integrity_probe.h"
#include "customrom/property_integrity_internal.h"
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace customrom::detail {

    size_t align_up(size_t value) {
        return (value + (kByteAlignment - 1)) & ~(kByteAlignment - 1);
    }

    bool is_skipped_entry(const char *name) {
        if (name == nullptr) {
            return true;
        }
        return std::strcmp(name, ".") == 0 ||
               std::strcmp(name, "..") == 0 ||
               kSerialFilename == name ||
               kPropertyInfoFilename == name;
    }

    bool starts_with_ro(const std::string &name) {
        return name.rfind("ro.", 0) == 0;
    }

    bool is_detect_property(std::string_view name) {
        for (std::string_view property: kDetectProperties) {
            if (property == name) {
                return true;
            }
        }
        return false;
    }

    std::string hex_u32(uint32_t value) {
        std::ostringstream stream;
        stream << "0x" << std::hex << std::nouppercase << value;
        return stream.str();
    }

    int android_sdk_level() {
        char value[PROP_VALUE_MAX] = {0};
        if (__system_property_get("ro.build.version.sdk", value) <= 0) {
            return 0;
        }
        return std::atoi(value);
    }

    std::optional<std::string> read_selinux_context(const std::string &path) {
        char attr[256] = {0};
        const ssize_t length = lgetxattr(path.c_str(), kContextLabel, attr, sizeof(attr) - 1);
        if (length < 0) {
            return std::nullopt;
        }
        attr[length] = '\0';
        return std::string(attr);
    }

    std::optional<PropertyIntegrityFinding> build_area_finding(
            const std::string &context,
            const std::vector<std::string> &problems
    ) {
        if (problems.empty()) {
            return std::nullopt;
        }

        PropertyIntegrityFinding finding;
        finding.category = "Prop area";
        finding.signal = context;
        finding.summary = "Abnormal prop area";
        finding.detail = problems.front();
        for (size_t index = 1; index < problems.size(); ++index) {
            finding.detail += "; ";
            finding.detail += problems[index];
        }
        return finding;
    }

    std::optional<PropertyIntegrityFinding> check_area_permissions(
            const std::string &path,
            const std::string &context
    ) {
        struct stat st {};
        if (stat(path.c_str(), &st) != 0) {
            return std::nullopt;
        }

        std::vector<std::string> problems;
        const auto mode = static_cast<unsigned>(st.st_mode & 07777);
        if (mode != 0444 || st.st_uid != 0 || st.st_gid != 0) {
            std::ostringstream stream;
            stream << "mode=" << std::oct << mode << std::dec
                   << " uid=" << st.st_uid
                   << " gid=" << st.st_gid;
            problems.push_back(stream.str());
        }

        if (const auto label = read_selinux_context(path); label.has_value() &&
                *label != context) {
            problems.push_back("selinux=" + *label + " expected=" + context);
        }

        return build_area_finding(context, problems);
    }

    bool has_tail_bytes(const std::array<char, PROP_VALUE_MAX> &value) {
        bool seen_terminator = false;
        for (char byte: value) {
            if (!seen_terminator) {
                if (byte == '\0') {
                    seen_terminator = true;
                }
                continue;
            }
            if (byte != '\0') {
                return true;
            }
        }
        return !seen_terminator;
    }

}  // namespace customrom::detail


namespace customrom {

    using namespace detail;

    PropertyIntegritySnapshot scan_property_integrity() {
        PropertyIntegritySnapshot snapshot;

        DIR *directory = opendir(kPropDir);
        if (directory == nullptr) {
            return snapshot;
        }

        const bool mark_dirty_backup = android_sdk_level() >= 30;
        while (dirent *entry = readdir(directory)) {
            if (is_skipped_entry(entry->d_name)) {
                continue;
            }

            const std::string context(entry->d_name);
            const std::string path = std::string(kPropDir) + "/" + context;
            const auto area_perm_finding = check_area_permissions(path, context);
            const auto area = scan_area(path, context, mark_dirty_backup);
            if (!area.has_value()) {
                if (area_perm_finding.has_value()) {
                    snapshot.available = true;
                    ++snapshot.context_count;
                    add_area_anomaly(
                            snapshot,
                            area_perm_finding->signal,
                            area_perm_finding->detail
                    );
                }
                continue;
            }

            snapshot.available = true;
            ++snapshot.context_count;

            if (area_perm_finding.has_value()) {
                add_area_anomaly(snapshot, area_perm_finding->signal, area_perm_finding->detail);
            } else if (!area->holes.empty()) {
                std::ostringstream detail;
                detail << "Found hole in prop area: " << context;
                detail << " (" << area->holes.size() << " hole(s))";
                detail << " ranges ";
                const size_t sample_count = std::min(area->holes.size(), static_cast<size_t>(3));
                for (size_t index = 0; index < sample_count; ++index) {
                    if (index > 0) {
                        detail << ", ";
                    }
                    detail << '@' << hex_u32(area->holes[index].offset)
                           << '+' << area->holes[index].length;
                }
                if (area->holes.size() > sample_count) {
                    detail << ", ...";
                }
                add_area_anomaly(snapshot, context, detail.str());
            }

            for (const auto &property: area->properties) {
                inspect_property(snapshot, property);
            }
        }

        closedir(directory);
        return snapshot;
    }

}  // namespace customrom
