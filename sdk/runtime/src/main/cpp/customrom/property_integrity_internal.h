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

    constexpr const char *kPropDir = "/dev/__properties__";

    constexpr std::string_view kSerialFilename = "properties_serial";

    constexpr std::string_view kPropertyInfoFilename = "property_info";

    constexpr uint32_t kPropAreaMagic = 0x504f5250U;

    constexpr uint32_t kPropAreaVersion = 0xfc6ed0abU;

    constexpr uint32_t kLongFlag = 1U << 16;

    constexpr uint32_t kSerialResidueMask = 0x00fffffeU;

    constexpr size_t kByteAlignment = 4;

    constexpr size_t kDirtyBackupAreaSize = PROP_VALUE_MAX;

    constexpr const char *kContextLabel = "security.selinux";

#ifdef O_NOFOLLOW
    constexpr int kOpenReadFlags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
#else
    constexpr int kOpenReadFlags = O_RDONLY | O_CLOEXEC;
#endif

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

    struct DiskPropAreaHeader {
        uint32_t bytes_used;
        uint32_t serial;
        uint32_t magic;
        uint32_t version;
        uint32_t reserved[28];
        uint8_t data[0];
    };

    struct DiskPropTrieNode {
        uint32_t namelen;
        uint32_t prop;
        uint32_t left;
        uint32_t right;
        uint32_t children;
        char name[0];
    };

    struct DiskLongProperty {
        char error_message[56];
        uint32_t offset;
    };

    struct DiskPropInfo {
        uint32_t serial;
        union {
            char value[PROP_VALUE_MAX];
            DiskLongProperty long_property;
        };
        char name[0];
    };

    struct HoleRun {
        uint32_t offset = 0;
        size_t length = 0;
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
        std::vector<HoleRun> holes;
        std::vector<ParsedProperty> properties;
    };

    size_t align_up(size_t value);

    bool is_skipped_entry(const char *name);

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

    class PropAreaParser {
    public:
        PropAreaParser(const uint8_t *data, size_t bytes_used, std::string context,
                       bool mark_dirty_backup)
                : data_(data),
                  bytes_used_(bytes_used),
                  context_(std::move(context)),
                  occupied_(bytes_used, 0),
                  mark_dirty_backup_(mark_dirty_backup) {}

        bool parse(std::vector<HoleRun> *holes, std::vector<ParsedProperty> *properties) {
            if (holes == nullptr || properties == nullptr || data_ == nullptr) {
                return false;
            }

            const auto *root = object_at<DiskPropTrieNode>(0);
            if (root == nullptr || root->namelen != 0) {
                return false;
            }

            if (!mark_range(0, sizeof(DiskPropTrieNode))) {
                return false;
            }
            if (mark_dirty_backup_ &&
                !mark_range(static_cast<uint32_t>(sizeof(DiskPropTrieNode)),
                            kDirtyBackupAreaSize)) {
                return false;
            }

            properties_ = properties;
            if (!visit_root(root)) {
                return false;
            }

            return collect_holes(holes);
        }

    private:
        template<typename T>
        const T *object_at(uint32_t offset) const {
            if (offset > bytes_used_) {
                return nullptr;
            }
            if (bytes_used_ - offset < sizeof(T)) {
                return nullptr;
            }
            return reinterpret_cast<const T *>(data_ + offset);
        }

        bool visit_root(const DiskPropTrieNode *root) {
            return visit_trie(root->left) &&
                   visit_trie(root->right) &&
                   visit_trie(root->children) &&
                   visit_prop(root->prop);
        }

        bool visit_trie(uint32_t offset) {
            if (offset == 0) {
                return true;
            }
            if (!visited_nodes_.insert(offset).second) {
                return true;
            }

            const auto *node = object_at<DiskPropTrieNode>(offset);
            if (node == nullptr) {
                return false;
            }

            const uint32_t name_offset =
                    offset + static_cast<uint32_t>(sizeof(DiskPropTrieNode));
            const auto name_length = bounded_c_string_length(name_offset);
            if (!name_length.has_value() || *name_length != node->namelen) {
                return false;
            }

            const size_t allocation_size = align_up(
                    sizeof(DiskPropTrieNode) + node->namelen + 1U);
            if (!mark_range(offset, allocation_size)) {
                return false;
            }

            return visit_trie(node->left) &&
                   visit_trie(node->right) &&
                   visit_trie(node->children) &&
                   visit_prop(node->prop);
        }

        bool visit_prop(uint32_t offset) {
            if (offset == 0) {
                return true;
            }
            if (!visited_props_.insert(offset).second) {
                return true;
            }

            const auto *prop = object_at<DiskPropInfo>(offset);
            if (prop == nullptr) {
                return false;
            }

            const uint32_t name_offset = offset + static_cast<uint32_t>(sizeof(DiskPropInfo));
            const auto name_length = bounded_c_string_length(name_offset);
            if (!name_length.has_value()) {
                return false;
            }

            const size_t allocation_size = align_up(sizeof(DiskPropInfo) + *name_length + 1U);
            if (!mark_range(offset, allocation_size)) {
                return false;
            }

            const std::string property_name(
                    reinterpret_cast<const char *>(data_ + name_offset),
                    *name_length
            );

            if (is_detect_property(property_name)) {
                ParsedProperty entry;
                entry.context = context_;
                entry.name = property_name;
                entry.serial = prop->serial;
                entry.is_long = (prop->serial & kLongFlag) != 0;

                if (entry.is_long) {
                    const uint32_t relative_offset = prop->long_property.offset;
                    if (relative_offset >= sizeof(DiskPropInfo)) {
                        const uint32_t long_value_offset = offset + relative_offset;
                        const auto value_length = bounded_c_string_length(long_value_offset);
                        if (value_length.has_value()) {
                            const auto copy_length = std::min(
                                    *value_length,
                                    static_cast<size_t>(PROP_VALUE_MAX - 1)
                            );
                            std::memcpy(
                                    entry.value.data(),
                                    data_ + long_value_offset,
                                    copy_length
                            );
                            entry.value[copy_length] = '\0';
                        }
                    }
                } else {
                    std::memcpy(entry.value.data(), prop->value, entry.value.size());
                }

                properties_->push_back(std::move(entry));
            }

            if ((prop->serial & kLongFlag) == 0) {
                return true;
            }

            const uint32_t relative_offset = prop->long_property.offset;
            if (relative_offset < sizeof(DiskPropInfo)) {
                return false;
            }

            const uint32_t long_value_offset = offset + relative_offset;
            if (long_value_offset >= bytes_used_) {
                return false;
            }

            const auto value_length = bounded_c_string_length(long_value_offset);
            if (!value_length.has_value()) {
                return false;
            }

            return mark_range(long_value_offset, align_up(*value_length + 1U));
        }

        std::optional<size_t> bounded_c_string_length(uint32_t offset) const {
            if (offset >= bytes_used_) {
                return std::nullopt;
            }
            const void *terminator = std::memchr(data_ + offset, '\0', bytes_used_ - offset);
            if (terminator == nullptr) {
                return std::nullopt;
            }
            return static_cast<const uint8_t *>(terminator) - (data_ + offset);
        }

        bool mark_range(uint32_t offset, size_t size) {
            if (size == 0) {
                return true;
            }
            if (offset % kByteAlignment != 0 || size % kByteAlignment != 0) {
                return false;
            }
            if (offset > bytes_used_ || size > bytes_used_ - offset) {
                return false;
            }
            std::fill(
                    occupied_.begin() + static_cast<std::ptrdiff_t>(offset),
                    occupied_.begin() + static_cast<std::ptrdiff_t>(offset + size),
                    1
            );
            return true;
        }

        bool collect_holes(std::vector<HoleRun> *holes) const {
            size_t index = 0;
            while (index < bytes_used_) {
                if (occupied_[index] != 0) {
                    ++index;
                    continue;
                }

                const size_t start = index;
                while (index < bytes_used_ && occupied_[index] == 0) {
                    ++index;
                }
                const size_t length = index - start;
                if (start % kByteAlignment != 0 || length < kByteAlignment ||
                    length % kByteAlignment != 0) {
                    return false;
                }
                holes->push_back(HoleRun{
                        .offset = static_cast<uint32_t>(start),
                        .length = length,
                });
            }
            return true;
        }

        const uint8_t *data_;
        size_t bytes_used_;
        std::string context_;
        std::vector<uint8_t> occupied_;
        bool mark_dirty_backup_ = false;
        std::vector<ParsedProperty> *properties_ = nullptr;
        std::unordered_set<uint32_t> visited_nodes_;
        std::unordered_set<uint32_t> visited_props_;
    };

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
