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

#pragma once

#include "customrom/property_integrity_probe.h"

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

    constexpr uint32_t kSerialResidueMask = 0x00fffffeU;

    constexpr const char *kContextLabel = "security.selinux";

    constexpr std::string_view kDetectProperties[] = {
            "ro.boot.vbmeta.device_state",
            "ro.boot.verifiedbootstate",
            "ro.boot.flash.locked",
            "ro.boot.veritymode",
            "ro.boot.warranty_bit",
            "ro.warranty_bit",
            "ro.debuggable",
            "ro.secure",
            "ro.build.type",
            "ro.build.tags",
            "ro.vendor.boot.warranty_bit",
            "ro.vendor.warranty_bit",
            "vendor.boot.vbmeta.device_state",
            "vendor.boot.verifiedbootstate",
            "ro.bootmode",
            "ro.boot.mode",
            "vendor.boot.mode",
            "ro.dalvik.vm.native.bridge",
    };

    struct ParsedProperty {
        std::string context;
        std::string name;
        uint32_t serial = 0;
        bool is_long = false;
        std::array<char, PROP_VALUE_MAX> value{};
    };

    struct AreaScanResult {
        bool parsed = false;
        std::vector<systemproperties::HoleRun> holes;
        std::vector<ParsedProperty> properties;
    };

    bool starts_with_ro(const std::string &name);

    bool is_detect_property(std::string_view name);

    std::string hex_u32(uint32_t value);

    int android_sdk_level();

    std::optional<std::string> read_selinux_context(const std::string &path);

    std::optional<PropertyIntegrityFinding> build_area_finding(
            const std::string &context,
            const std::vector<std::string> &problems
    );

    std::optional<PropertyIntegrityFinding> check_area_permissions(
            const std::string &path,
            const std::string &context
    );

    bool has_tail_bytes(const std::array<char, PROP_VALUE_MAX> &value);

    std::optional<AreaScanResult> scan_area(
            const std::string &path,
            const std::string &context,
            bool mark_dirty_backup
    );

    void add_area_anomaly(
            PropertyIntegritySnapshot &snapshot,
            const std::string &signal,
            const std::string &detail
    );

    void add_property_anomaly(
            PropertyIntegritySnapshot &snapshot,
            const std::string &category,
            const std::string &signal,
            const std::string &summary,
            const std::string &detail
    );

    void inspect_property(
            PropertyIntegritySnapshot &snapshot,
            const ParsedProperty &property
    );

}  // namespace customrom::detail
