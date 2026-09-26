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

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstring>
#include <string>

namespace duckdetector::nativeroot::permission_boundary {

    namespace {

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

    }  // namespace

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

}  // namespace duckdetector::nativeroot::permission_boundary
