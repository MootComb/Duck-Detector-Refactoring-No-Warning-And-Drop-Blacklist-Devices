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

#include "nativeroot/probes/permission_boundary_netlink.h"

#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cstdio>
#include <string>

namespace duckdetector::nativeroot::permission_boundary {

    void append_line(std::string &target, const std::string &line) {
        target += line;
        target += '\n';
    }

    ScopedFd create_netlink_route_socket() {
        const int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0) {
            return ScopedFd(-1);
        }

        struct timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 250000; // 250 ms timeout to prevent indefinite blocking in recv()
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        return ScopedFd(fd);
    }

    bool is_valid_physical_mac(const unsigned char *mac) {
        if (!mac) return false;
        if ((mac[0] & 0x01) != 0) return false; // Multicast
        if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
            mac[3] == 0 && mac[4] == 0 && mac[5] == 0) return false; // All-zero
        if (mac[0] == 0x02 && mac[1] == 0 && mac[2] == 0 &&
            mac[3] == 0 && mac[4] == 0 && mac[5] == 0) return false; // AOSP dummy mask
        return true;
    }

    std::string format_mac_address(const unsigned char *mac) {
        char buf[20];
        std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return buf;
    }

    std::string scope_label(const int api_level, const int target_sdk) {
        return "API " + std::to_string(api_level) + ", targetSdk " + std::to_string(target_sdk);
    }

}  // namespace duckdetector::nativeroot::permission_boundary
