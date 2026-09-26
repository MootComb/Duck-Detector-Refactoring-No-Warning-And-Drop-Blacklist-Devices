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

#ifndef DUCKDETECTOR_NATIVEROOT_PROBES_PERMISSION_BOUNDARY_NETLINK_H
#define DUCKDETECTOR_NATIVEROOT_PROBES_PERMISSION_BOUNDARY_NETLINK_H

#include "nativeroot/common/types.h"

#include <unistd.h>

#include <string>

// The netlink plumbing the permission boundary checks share, and the checks themselves.
namespace duckdetector::nativeroot::permission_boundary {

    void append_line(std::string &target, const std::string &line);

    // RAII file descriptor wrapper to ensure sockets are always closed.
    class ScopedFd {
    public:
        explicit ScopedFd(const int fd = -1) : fd_(fd) {}
        ~ScopedFd() { reset(); }

        ScopedFd(const ScopedFd &) = delete;
        ScopedFd &operator=(const ScopedFd &) = delete;

        ScopedFd(ScopedFd &&other) noexcept : fd_(other.release()) {}
        ScopedFd &operator=(ScopedFd &&other) noexcept {
            if (this != &other) {
                reset(other.release());
            }
            return *this;
        }

        int get() const { return fd_; }
        bool valid() const { return fd_ >= 0; }

        void reset(const int new_fd = -1) {
            if (fd_ >= 0) {
                close(fd_);
            }
            fd_ = new_fd;
        }

        int release() {
            const int tmp = fd_;
            fd_ = -1;
            return tmp;
        }

    private:
        int fd_ = -1;
    };

    // Create and configure a NETLINK_ROUTE raw socket with a 250ms receive timeout.
    ScopedFd create_netlink_route_socket();

    // Validate that a MAC address is a real physical unicast address:
    // 1. Not multicast (LSB of first byte == 1).
    // 2. Not all zeros (00:00:00:00:00:00).
    // 3. Not AOSP privacy dummy mask (02:00:00:00:00:00).
    bool is_valid_physical_mac(const unsigned char *mac);

    std::string format_mac_address(const unsigned char *mac);

    std::string scope_label(const int api_level, const int target_sdk);

    // Whether this process can dump RTM_GETLINK and read a physical interface's MAC address.
    void check_netlink_link_boundary(ProbeResult &result, const int api_level, const int target_sdk);

    // Whether this process can dump RTM_GETNEIGH and read a unicast LAN neighbour.
    void check_netlink_neigh_boundary(ProbeResult &result, const int api_level, const int target_sdk);

}  // namespace duckdetector::nativeroot::permission_boundary

#endif  // DUCKDETECTOR_NATIVEROOT_PROBES_PERMISSION_BOUNDARY_NETLINK_H
