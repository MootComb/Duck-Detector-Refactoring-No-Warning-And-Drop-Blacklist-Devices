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
#include "nativeroot/probes/permission_boundary_probe.h"

#include <arpa/inet.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>

#ifndef NDA_RTA
#define NDA_RTA(r) ((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n, sizeof(struct ndmsg))
#endif

namespace duckdetector::nativeroot::permission_boundary {

    namespace {

        // RTM_GETNEIGH needs nlmsg_getneigh only once libsepol writes
        // POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH, which starts with Android 13, and sepolicy still
        // grants it to apps targeting SDK 31 or lower (untrusted_app_30.te and older), as CTS expects.
        bool getneigh_restricted(const int api_level, const int target_sdk) {
            return api_level >= 33 && target_sdk >= 32;
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

    }  // namespace

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

}  // namespace duckdetector::nativeroot::permission_boundary
