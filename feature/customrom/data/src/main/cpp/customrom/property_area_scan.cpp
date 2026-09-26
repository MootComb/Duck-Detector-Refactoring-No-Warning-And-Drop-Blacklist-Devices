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

#include "systemproperties/prop_area_file.h"
#include "systemproperties/prop_area_format.h"
#include "systemproperties/prop_area_parser.h"

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

    namespace {

        void collect_detect_property(
                const systemproperties::PropAreaParser &area,
                const uint32_t offset,
                const systemproperties::DiskPropInfo &prop,
                const std::string_view name,
                const std::string &context,
                std::vector<ParsedProperty> *properties
        ) {
            const std::string property_name(name);

            if (is_detect_property(property_name)) {
                ParsedProperty entry;
                entry.context = context;
                entry.name = property_name;
                entry.serial = prop.serial;
                entry.is_long = (prop.serial & systemproperties::kLongFlag) != 0;

                if (entry.is_long) {
                    const uint32_t relative_offset = prop.long_property.offset;
                    if (relative_offset >= sizeof(systemproperties::DiskPropInfo)) {
                        const uint32_t long_value_offset = offset + relative_offset;
                        const auto value_length = area.bounded_c_string_length(long_value_offset);
                        if (value_length.has_value()) {
                            const auto copy_length = std::min(
                                    *value_length,
                                    static_cast<size_t>(PROP_VALUE_MAX - 1)
                            );
                            std::memcpy(
                                    entry.value.data(),
                                    area.data() + long_value_offset,
                                    copy_length
                            );
                            entry.value[copy_length] = '\0';
                        }
                    }
                } else {
                    std::memcpy(entry.value.data(), prop.value, entry.value.size());
                }

                properties->push_back(std::move(entry));
            }
        }

    }  // namespace

    std::optional<AreaScanResult> scan_area(
            const std::string &path,
            const std::string &context,
            bool mark_dirty_backup
    ) {
        AreaScanResult result;
        auto holes = systemproperties::scan_prop_area_file(
                path,
                mark_dirty_backup,
                [&context, &result](
                        const systemproperties::PropAreaParser &area,
                        const uint32_t offset,
                        const systemproperties::DiskPropInfo &prop,
                        const std::string_view name
                ) {
                    collect_detect_property(area, offset, prop, name, context, &result.properties);
                }
        );
        if (!holes.has_value()) {
            return std::nullopt;
        }
        result.parsed = true;
        result.holes = std::move(*holes);
        return result;
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
        if ((property.serial & systemproperties::kLongFlag) == 0 &&
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
