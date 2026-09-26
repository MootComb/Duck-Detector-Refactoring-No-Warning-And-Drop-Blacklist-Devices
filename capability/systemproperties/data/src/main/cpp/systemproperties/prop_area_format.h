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

#include <sys/system_properties.h>

#include <cstddef>
#include <cstdint>

// The layout of a bionic property area, one file per SELinux context under /dev/__properties__.
// It mirrors prop_area, prop_bt and prop_info in bionic's
// libc/system_properties/include/system_properties/prop_area.h and prop_info.h, and the magic and
// version that libc/system_properties/prop_area.cpp writes and checks.
namespace systemproperties {

    constexpr uint32_t kPropAreaMagic = 0x504f5250U;

    constexpr uint32_t kPropAreaVersion = 0xfc6ed0abU;

    constexpr uint32_t kLongFlag = 1U << 16;

    constexpr size_t kByteAlignment = 4;

    // From Android 11, bionic reserves a PROP_VALUE_MAX block right after the root node for the
    // old value of a property being written; Android 10's areas start allocating right there.
    constexpr size_t kDirtyBackupAreaSize = PROP_VALUE_MAX;

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

}  // namespace systemproperties
