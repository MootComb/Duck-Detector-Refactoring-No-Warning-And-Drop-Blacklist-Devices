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

#include "systemproperties/prop_area_parser.h"

#include <algorithm>
#include <cstring>

namespace systemproperties {

    size_t align_up(size_t value) {
        return (value + (kByteAlignment - 1)) & ~(kByteAlignment - 1);
    }

    PropAreaParser::PropAreaParser(const uint8_t *data, size_t bytes_used, bool mark_dirty_backup)
            : data_(data),
              bytes_used_(bytes_used),
              occupied_(bytes_used, 0),
              mark_dirty_backup_(mark_dirty_backup) {}

    template<typename T>
    const T *PropAreaParser::object_at(uint32_t offset) const {
        if (offset > bytes_used_) {
            return nullptr;
        }
        if (bytes_used_ - offset < sizeof(T)) {
            return nullptr;
        }
        return reinterpret_cast<const T *>(data_ + offset);
    }

    bool PropAreaParser::parse(std::vector<HoleRun> *holes, const PropertyVisitor &visit_property) {
        if (holes == nullptr || data_ == nullptr) {
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

        visit_property_ = visit_property ? &visit_property : nullptr;
        const bool walked = visit_root(root);
        visit_property_ = nullptr;
        if (!walked) {
            return false;
        }

        return collect_holes(holes);
    }

    const uint8_t *PropAreaParser::data() const {
        return data_;
    }

    std::optional<size_t> PropAreaParser::bounded_c_string_length(uint32_t offset) const {
        if (offset >= bytes_used_) {
            return std::nullopt;
        }
        const void *terminator = std::memchr(data_ + offset, '\0', bytes_used_ - offset);
        if (terminator == nullptr) {
            return std::nullopt;
        }
        return static_cast<const uint8_t *>(terminator) - (data_ + offset);
    }

    bool PropAreaParser::visit_root(const DiskPropTrieNode *root) {
        return visit_trie(root->left) &&
               visit_trie(root->right) &&
               visit_trie(root->children) &&
               visit_prop(root->prop);
    }

    bool PropAreaParser::visit_trie(uint32_t offset) {
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

    bool PropAreaParser::visit_prop(uint32_t offset) {
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

        if (visit_property_ != nullptr) {
            (*visit_property_)(
                    *this,
                    offset,
                    *prop,
                    std::string_view(reinterpret_cast<const char *>(data_ + name_offset),
                                     *name_length)
            );
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

    bool PropAreaParser::mark_range(uint32_t offset, size_t size) {
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

    bool PropAreaParser::collect_holes(std::vector<HoleRun> *holes) const {
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

}  // namespace systemproperties
