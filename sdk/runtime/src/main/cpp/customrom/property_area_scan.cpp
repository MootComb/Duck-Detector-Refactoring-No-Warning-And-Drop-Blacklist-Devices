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

    std::optional<AreaScanResult> scan_area(
            const std::string &path,
            const std::string &context,
            bool mark_dirty_backup
    ) {
        const int fd = open(path.c_str(), kOpenReadFlags);
        if (fd < 0) {
            return std::nullopt;
        }

        struct stat stat_buffer {};
        if (fstat(fd, &stat_buffer) != 0 || !S_ISREG(stat_buffer.st_mode)) {
            close(fd);
            return std::nullopt;
        }

        if (static_cast<size_t>(stat_buffer.st_size) < sizeof(DiskPropAreaHeader)) {
            close(fd);
            return std::nullopt;
        }

        void *mapping = mmap(nullptr, static_cast<size_t>(stat_buffer.st_size), PROT_READ,
                             MAP_PRIVATE, fd, 0);
        close(fd);
        if (mapping == MAP_FAILED) {
            return std::nullopt;
        }

        const auto *header = reinterpret_cast<const DiskPropAreaHeader *>(mapping);
        const size_t data_size =
                static_cast<size_t>(stat_buffer.st_size) - sizeof(DiskPropAreaHeader);
        const size_t minimum_bytes_used = sizeof(DiskPropTrieNode) +
                                          (mark_dirty_backup ? kDirtyBackupAreaSize : 0);
        if (header->magic != kPropAreaMagic ||
            header->version != kPropAreaVersion ||
            header->bytes_used > data_size ||
            header->bytes_used < minimum_bytes_used) {
            munmap(mapping, static_cast<size_t>(stat_buffer.st_size));
            return std::nullopt;
        }

        AreaScanResult result;
        PropAreaParser parser(
                header->data,
                header->bytes_used,
                context,
                mark_dirty_backup
        );
        result.parsed = parser.parse(&result.holes, &result.properties);
        munmap(mapping, static_cast<size_t>(stat_buffer.st_size));
        return result.parsed ? std::optional<AreaScanResult>(std::move(result)) : std::nullopt;
    }

    void add_area_anomaly(
            PropertyIntegritySnapshot &snapshot,
            const std::string &signal,
            const std::string &detail
    ) {
        snapshot.findings.push_back(PropertyIntegrityFinding{
                .category = "Prop area",
                .signal = signal,
                .summary = "Abnormal prop area",
                .detail = detail,
        });
        if (snapshot.area_anomaly_count < 16) {
            ++snapshot.area_anomaly_count;
        }
    }

    void add_property_anomaly(
            PropertyIntegritySnapshot &snapshot,
            const std::string &category,
            const std::string &signal,
            const std::string &summary,
            const std::string &detail
    ) {
        snapshot.findings.push_back(PropertyIntegrityFinding{
                .category = category,
                .signal = signal,
                .summary = summary,
                .detail = detail,
        });
        if (snapshot.item_anomaly_count < 16) {
            ++snapshot.item_anomaly_count;
        }
    }

    void inspect_property(
            PropertyIntegritySnapshot &snapshot,
            const ParsedProperty &property
    ) {
        if ((property.serial & kLongFlag) == 0 &&
            (property.serial & kSerialResidueMask) != 0) {
            add_property_anomaly(
                    snapshot,
                    "Prop serial",
                    property.name,
                    "Abnormal prop serial",
                    property.context + " serial=" + hex_u32(property.serial)
            );
        }

        if (!property.is_long && starts_with_ro(property.name) && has_tail_bytes(property.value)) {
            add_property_anomaly(
                    snapshot,
                    "Prop tail",
                    property.name,
                    "Residual prop value",
                    property.context + " contains data after the first NUL byte"
            );
        }
    }

}  // namespace customrom::detail
