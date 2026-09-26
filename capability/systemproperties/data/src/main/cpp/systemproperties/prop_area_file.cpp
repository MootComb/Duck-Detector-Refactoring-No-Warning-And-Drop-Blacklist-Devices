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

#include "systemproperties/prop_area_file.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <string_view>
#include <utility>

namespace systemproperties {

    namespace {

        constexpr std::string_view kSerialFilename = "properties_serial";

        constexpr std::string_view kPropertyInfoFilename = "property_info";

#ifdef O_NOFOLLOW
        constexpr int kOpenReadFlags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
#else
        constexpr int kOpenReadFlags = O_RDONLY | O_CLOEXEC;
#endif

    }  // namespace

    bool is_skipped_entry(const char *name) {
        if (name == nullptr) {
            return true;
        }
        return std::strcmp(name, ".") == 0 ||
               std::strcmp(name, "..") == 0 ||
               kSerialFilename == name ||
               kPropertyInfoFilename == name;
    }

    std::optional<std::vector<HoleRun>> scan_prop_area_file(
            const std::string &path,
            bool mark_dirty_backup,
            const PropAreaParser::PropertyVisitor &visit_property
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

        std::vector<HoleRun> holes;
        PropAreaParser parser(header->data, header->bytes_used, mark_dirty_backup);
        const bool parsed = parser.parse(&holes, visit_property);
        munmap(mapping, static_cast<size_t>(stat_buffer.st_size));
        return parsed ? std::optional<std::vector<HoleRun>>(std::move(holes)) : std::nullopt;
    }

}  // namespace systemproperties
