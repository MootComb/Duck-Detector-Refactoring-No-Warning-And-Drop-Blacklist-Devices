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

#include "systemproperties/prop_area_format.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace systemproperties {

    // A run of bytes below bytes_used that no trie node, property or long value occupies.
    struct HoleRun {
        uint32_t offset = 0;
        size_t length = 0;
    };

    size_t align_up(size_t value);

    // Walks a property area's trie from the root node, marks every allocation it reaches and
    // reports the runs left unmarked. The walk fails on any reference, name or allocation that
    // does not fit the area.
    class PropAreaParser {
    public:
        // Called for each property once its prop_info allocation is marked, before its long
        // value is checked, so a walk that fails later has still reported it.
        using PropertyVisitor = std::function<void(
                const PropAreaParser &area,
                uint32_t offset,
                const DiskPropInfo &prop,
                std::string_view name
        )>;

        PropAreaParser(const uint8_t *data, size_t bytes_used, bool mark_dirty_backup);

        bool parse(std::vector<HoleRun> *holes, const PropertyVisitor &visit_property = {});

        const uint8_t *data() const;

        std::optional<size_t> bounded_c_string_length(uint32_t offset) const;

    private:
        template<typename T>
        const T *object_at(uint32_t offset) const;

        bool visit_root(const DiskPropTrieNode *root);

        bool visit_trie(uint32_t offset);

        bool visit_prop(uint32_t offset);

        bool mark_range(uint32_t offset, size_t size);

        bool collect_holes(std::vector<HoleRun> *holes) const;

        const uint8_t *data_;
        size_t bytes_used_;
        std::vector<uint8_t> occupied_;
        bool mark_dirty_backup_;
        const PropertyVisitor *visit_property_ = nullptr;
        std::unordered_set<uint32_t> visited_nodes_;
        std::unordered_set<uint32_t> visited_props_;
    };

}  // namespace systemproperties
