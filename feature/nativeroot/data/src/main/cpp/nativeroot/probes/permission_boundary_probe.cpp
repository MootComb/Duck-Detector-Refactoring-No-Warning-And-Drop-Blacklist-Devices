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

#include "nativeroot/probes/permission_boundary_probe.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include <android/api-level.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef NDA_RTA
#define NDA_RTA(r) ((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n, sizeof(struct ndmsg))
#endif

namespace duckdetector::nativeroot {

    namespace {

        void append_line(std::string &target, const std::string &line) {
            target += line;
            target += '\n';
        }

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

        // Strictly inspect physical Wi-Fi (wlan*, swlan*) and physical Ethernet (eth*) interfaces.
        // Virtual/dummy/cellular interfaces (dummy*, rmnet*, sit*, tun*, tap*, p2p*, lo) are ignored.
        bool is_target_physical_interface(const std::string &ifname) {
            if (ifname.empty()) {
                return false;
            }
            if (ifname.rfind("wlan", 0) == 0 || ifname.rfind("swlan", 0) == 0 ||
                ifname.rfind("eth", 0) == 0) {
                return true;
            }
            return false;
        }

        // Validate that a MAC address is a real physical unicast address:
        // 1. Not multicast (LSB of first byte == 1).
        // 2. Not all zeros (00:00:00:00:00:00).
        // 3. Not AOSP privacy dummy mask (02:00:00:00:00:00).
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

        // RTM_GETLINK needs nlmsg_readpriv once the loaded policy carries
        // POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE, which libsepol writes from Android 11
        // (external/selinux libsepol/src/write.c; security/selinux/nlmsgtab.c in ACK). Android 11
        // and 12 still granted it to apps targeting SDK 29 or lower (system/sepolicy
        // untrusted_app_29.te and older). From Android 13 no untrusted app holds it
        // (app_neverallows.te), and CTS expects EACCES (SELinuxTargetSdkTestBase).
        bool getlink_restricted(const int api_level, const int target_sdk) {
            if (api_level < 30) return false;
            return api_level >= 33 || target_sdk >= 30;
        }

        // RTM_GETNEIGH needs nlmsg_getneigh only once libsepol writes
        // POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH, which starts with Android 13, and sepolicy still
        // grants it to apps targeting SDK 31 or lower (untrusted_app_30.te and older), as CTS expects.
        bool getneigh_restricted(const int api_level, const int target_sdk) {
            return api_level >= 33 && target_sdk >= 32;
        }

        std::string scope_label(const int api_level, const int target_sdk) {
            return "API " + std::to_string(api_level) + ", targetSdk " + std::to_string(target_sdk);
        }

        // Validate IPv4 unicast host address:
        // Filter out 0.0.0.0, 127.0.0.0/8 (loopback), 224.0.0.0/4 (multicast), and 255.255.255.255 (broadcast).
        bool is_valid_unicast_ipv4(const struct in_addr &in) {
            const uint32_t ip_host = ntohl(in.s_addr);
            if (ip_host == 0) return false;
            if ((ip_host & 0xff000000) == 0x7f000000) return false;
            if (ip_host >= 0xe0000000 && ip_host <= 0xefffffff) return false;
            if (ip_host == 0xffffffff) return false;
            return true;
        }

        /*
         * Netlink RTM_GETLINK dump query & hardware MAC leak check.
         *
         * Background:
         * Android 11+ (API 30+) kernel commit b4563881284b ("ANDROID: selinux: modify RTM_GETLINK permission")
         * introduced POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE (p->android_netlink_route) and AOSP sepolicy:
         * neverallow { appdomain -shell } self:netlink_route_socket { nlmsg_read nlmsg_write };
         *
         * Android Kernel Vulnerability & bypass mechanism:
         * In older Android common kernels (addressed in change 3009995), policydb_write() failed to include
         * Android-specific configuration bits (POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE).
         * Consequently, if userspace or a root tool reloads policy via load_policy /sys/fs/selinux/policy,
         * or if Magisk/root sepolicy injection widens netlink permissions, the kernel drops the
         * POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE restriction.
         *
         * Enforced: sendto fails with EACCES. Only a process the restriction applies to is checked.
         * Not enforced: sendto succeeds; exposing a physical interface MAC is the finding.
         */
        void check_netlink_link_boundary(ProbeResult &result, const int api_level, const int target_sdk) {
            result.checked_count++;
            if (!getlink_restricted(api_level, target_sdk)) {
                append_line(result.extra_text, "Netlink link boundary: not applicable, Android lets this process send RTM_GETLINK (" +
                                               scope_label(api_level, target_sdk) + ").");
                return;
            }

            errno = 0;
            const ScopedFd sock = create_netlink_route_socket();
            if (!sock.valid()) {
                append_line(result.extra_text, "Netlink link boundary: not evaluated, socket creation failed (errno=" +
                                               std::to_string(errno) + ").");
                return;
            }

            // Standard 32-byte RTM_GETLINK dump request: nlmsghdr (16B) + rtgenmsg (16B)
            struct {
                struct nlmsghdr hdr;
                struct rtgenmsg gen;
            } req{};
            req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg)); // 32 bytes
            req.hdr.nlmsg_type = RTM_GETLINK;                          // 18 (0x12)
            req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;          // 0x301
            req.hdr.nlmsg_seq = 1;
            req.gen.rtgen_family = AF_UNSPEC;

            errno = 0;
            const ssize_t sent = sendto(sock.get(), &req, req.hdr.nlmsg_len, 0, nullptr, 0);
            const int send_err = errno;
            if (sent != static_cast<ssize_t>(req.hdr.nlmsg_len)) {
                if (send_err == EACCES) {
                    result.aux_flags |= kBoundaryAuxEvaluated;
                    append_line(result.extra_text, "Netlink link boundary: enforced, SELinux denied RTM_GETLINK (EACCES).");
                } else {
                    append_line(result.extra_text, "Netlink link boundary: not evaluated, sendto failed (errno=" +
                                                   std::to_string(send_err) + ").");
                }
                return;
            }
            result.aux_flags |= kBoundaryAuxEvaluated;

            // Receive and parse RTM_NEWLINK response to detect hardware MAC leakage
            char buffer[8192];
            ssize_t len = 0;
            bool mac_leak_detected = false;
            std::string leaked_ifname;
            std::string leaked_mac;

            while ((len = recv(sock.get(), buffer, sizeof(buffer), 0)) > 0) {
                const auto *nlh = reinterpret_cast<const struct nlmsghdr *>(buffer);
                for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
                    if (nlh->nlmsg_type == NLMSG_DONE) {
                        goto done_link_recv;
                    }
                    if (nlh->nlmsg_type == NLMSG_ERROR) {
                        continue;
                    }
                    if (nlh->nlmsg_type != RTM_NEWLINK) {
                        continue;
                    }

                    const auto *ifi = static_cast<const struct ifinfomsg *>(NLMSG_DATA(nlh));
                    if (ifi->ifi_flags & IFF_LOOPBACK) {
                        continue; // Skip loopback
                    }
                    if (!(ifi->ifi_flags & IFF_UP)) {
                        continue; // Skip inactive interfaces
                    }

                    const auto *rta = IFLA_RTA(ifi);
                    int rta_len = IFLA_PAYLOAD(nlh);
                    std::string ifname;
                    unsigned char mac_bytes[6]{};
                    bool has_mac = false;

                    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                        if (rta->rta_type == IFLA_IFNAME) {
                            ifname = reinterpret_cast<const char *>(RTA_DATA(rta));
                        } else if (rta->rta_type == IFLA_ADDRESS && RTA_PAYLOAD(rta) == 6) {
                            std::memcpy(mac_bytes, RTA_DATA(rta), 6);
                            has_mac = true;
                        }
                    }

                    // Only inspect targeted physical interfaces to avoid false positives on virtual devices
                    if (!is_target_physical_interface(ifname)) {
                        continue;
                    }

                    if (has_mac && is_valid_physical_mac(mac_bytes)) {
                        mac_leak_detected = true;
                        leaked_ifname = ifname;
                        leaked_mac = format_mac_address(mac_bytes);
                        goto done_link_recv;
                    }
                }
            }

        done_link_recv:
            if (mac_leak_detected) {
                result.hit_count++;

                Finding finding;
                finding.group = "PERMISSION_BOUNDARY";
                finding.label = "AF_NETLINK MAC Leak";
                finding.value = "Hardware MAC Exposed (" + leaked_ifname + ")";
                finding.severity = Severity::kDanger;
                finding.detail = "SELinux answered RTM_GETLINK and exposed the physical MAC of " + leaked_ifname +
                                 " (" + leaked_mac + ") although AOSP policy and CTS require a denial for this process (" +
                                 scope_label(api_level, target_sdk) + ").";
                result.findings.push_back(finding);
                append_line(result.extra_text, "Netlink link boundary: not enforced, physical MAC exposed on " + leaked_ifname +
                                               " (" + leaked_mac + ").");
            } else {
                append_line(result.extra_text, "Netlink link boundary: not enforced, RTM_GETLINK was answered but exposed no physical interface MAC.");
            }
        }

        /*
         * Netlink RTM_GETNEIGH dump query & ARP/neighbor table leak check.
         *
         * Background:
         * Android commit 5f409cbcf429 ("ANDROID: selinux: modify RTM_GETNEIGH{TBL}") introduced
         * POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH (p->android_netlink_getneigh) on API 30+/33+.
         *
         * Android Kernel Vulnerability & bypass mechanism:
         * When SELinux policy is reloaded via load_policy /sys/fs/selinux/policy on affected kernels,
         * the missing POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH config bit is omitted by policydb_write()
         * (see change 3009995), causing the kernel to stop checking getneigh permissions and allowing
         * sandboxed untrusted apps to dump the entire LAN ARP table.
         *
         * Enforced: sendto fails with EACCES. Only a process the restriction applies to is checked.
         * Not enforced: sendto succeeds; returning a unicast LAN neighbour (IP -> MAC) is the finding.
         */
        void check_netlink_neigh_boundary(ProbeResult &result, const int api_level, const int target_sdk) {
            result.checked_count++;
            if (!getneigh_restricted(api_level, target_sdk)) {
                append_line(result.extra_text, "Netlink neigh boundary: not applicable, Android lets this process send RTM_GETNEIGH (" +
                                               scope_label(api_level, target_sdk) + ").");
                return;
            }

            errno = 0;
            const ScopedFd sock = create_netlink_route_socket();
            if (!sock.valid()) {
                append_line(result.extra_text, "Netlink neigh boundary: not evaluated, socket creation failed (errno=" +
                                               std::to_string(errno) + ").");
                return;
            }

            struct {
                struct nlmsghdr hdr;
                struct ndmsg msg;
            } req{};
            req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
            req.hdr.nlmsg_type = RTM_GETNEIGH;
            req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
            req.hdr.nlmsg_seq = 2;
            req.msg.ndm_family = AF_INET;

            errno = 0;
            const ssize_t sent = sendto(sock.get(), &req, req.hdr.nlmsg_len, 0, nullptr, 0);
            const int send_err = errno;
            if (sent != static_cast<ssize_t>(req.hdr.nlmsg_len)) {
                if (send_err == EACCES) {
                    result.aux_flags |= kBoundaryAuxEvaluated;
                    append_line(result.extra_text, "Netlink neigh boundary: enforced, SELinux denied RTM_GETNEIGH (EACCES).");
                } else {
                    append_line(result.extra_text, "Netlink neigh boundary: not evaluated, sendto failed (errno=" +
                                                   std::to_string(send_err) + ").");
                }
                return;
            }
            result.aux_flags |= kBoundaryAuxEvaluated;

            char buffer[8192];
            ssize_t len = 0;
            bool neigh_leak_detected = false;
            std::string leaked_ip;
            std::string leaked_mac;

            while ((len = recv(sock.get(), buffer, sizeof(buffer), 0)) > 0) {
                const auto *nlh = reinterpret_cast<const struct nlmsghdr *>(buffer);
                for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
                    if (nlh->nlmsg_type == NLMSG_DONE) {
                        goto done_neigh_recv;
                    }
                    if (nlh->nlmsg_type == NLMSG_ERROR) {
                        continue;
                    }
                    if (nlh->nlmsg_type != RTM_NEWNEIGH) {
                        continue;
                    }

                    const auto *ndm = static_cast<const struct ndmsg *>(NLMSG_DATA(nlh));
                    // Skip incomplete, noarp, or failed states
                    if (ndm->ndm_state & (NUD_NOARP | NUD_FAILED | NUD_INCOMPLETE)) {
                        continue;
                    }

                    const auto *rta = NDA_RTA(ndm);
                    int rta_len = NDA_PAYLOAD(nlh);

                    unsigned char mac_bytes[6]{};
                    bool has_mac = false;
                    char ip_str[INET_ADDRSTRLEN]{};
                    bool is_unicast_ip = false;

                    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                        if (rta->rta_type == NDA_DST && RTA_PAYLOAD(rta) == sizeof(in_addr)) {
                            struct in_addr in{};
                            std::memcpy(&in, RTA_DATA(rta), sizeof(in));
                            if (is_valid_unicast_ipv4(in)) {
                                if (inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str))) {
                                    is_unicast_ip = true;
                                }
                            }
                        } else if (rta->rta_type == NDA_LLADDR && RTA_PAYLOAD(rta) == 6) {
                            std::memcpy(mac_bytes, RTA_DATA(rta), 6);
                            has_mac = true;
                        }
                    }

                    if (has_mac && is_unicast_ip && is_valid_physical_mac(mac_bytes)) {
                        neigh_leak_detected = true;
                        leaked_mac = format_mac_address(mac_bytes);
                        leaked_ip = ip_str;
                        goto done_neigh_recv;
                    }
                }
            }

        done_neigh_recv:
            if (neigh_leak_detected) {
                result.hit_count++;

                Finding finding;
                finding.group = "PERMISSION_BOUNDARY";
                finding.label = "AF_NETLINK Neighbor Leak";
                finding.value = "Hardware ARP/Neighbor Exposed";
                finding.severity = Severity::kDanger;
                finding.detail = "SELinux answered RTM_GETNEIGH and exposed a LAN neighbour (" +
                                 leaked_ip + " -> " + leaked_mac + ") although AOSP policy and CTS require a denial for this process (" +
                                 scope_label(api_level, target_sdk) + ").";
                result.findings.push_back(finding);
                append_line(result.extra_text, "Netlink neigh boundary: not enforced, LAN neighbour exposed (" +
                                               leaked_ip + " " + leaked_mac + ").");
            } else {
                append_line(result.extra_text, "Netlink neigh boundary: not enforced, RTM_GETNEIGH was answered but exposed no unicast neighbour.");
            }
        }

    }  // namespace

    ProbeResult run_permission_boundary_check() {
        ProbeResult result;
        const int api_level = android_get_device_api_level();
        const int target_sdk = android_get_application_target_sdk_version();

        check_netlink_link_boundary(result, api_level, target_sdk);
        check_netlink_neigh_boundary(result, api_level, target_sdk);

        return result;
    }

}  // namespace duckdetector::nativeroot
