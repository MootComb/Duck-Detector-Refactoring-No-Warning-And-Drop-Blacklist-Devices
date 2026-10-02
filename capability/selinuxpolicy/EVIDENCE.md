# SELinux policy capability evidence record

Status: reviewed

The SELinux policy capability asks the loaded policy questions an ordinary app cannot, from carrier processes, for the SELinux and LSPosed detectors: which contexts are valid, which access edges are allowed, and whether the policy was reloaded.

## Signals

### Context validity

- Observable signal: whether contexts such as u:r:magisk:s0 are valid in the loaded policy.
- Producing subsystem: the kernel's SELinux policy, through selinuxfs's context node.
- Mechanism: writing a context to /sys/fs/selinux/context succeeds only for contexts the loaded policy defines, so root-tool domains are valid only in a policy that added them.
- References: kernel/common security/selinux/selinuxfs.c (sel_write_context; the context node is world readable and writable).
- Applicability: carriers in app_zygote and dedicated processes; see SelinuxContextValidityCarrierManager.
- Visibility limits: a carrier that cannot start leaves the snapshot unavailable. ActivityManager answers that failure by stopping every service of the package (frameworks/base ProcessList.handleProcessStart -> forceStopPackageLocked), so helpers other detectors bound in the same scan stop with it. The SELinux and LSPosed detectors therefore share one carrier collection per scan, and once an app zygote carrier has been stopped before it connected, the scan's remaining app zygote carriers are reported unavailable without being started (`:core:platform` AppZygoteStartGate), so the package is stopped once rather than once per carrier.
- Result states: valid, invalid, unavailable.
- Interpretation: consumers decide which valid contexts are evidence.

### Dirty policy oracle

- Observable signal: allowed or denied answers for access edges stock policy denies.
- Producing subsystem: the loaded policy, through libselinux's selinux_check_access and selinuxfs's access node.
- Mechanism: the oracle computes the access vector for an edge; a control edge stock policy allows and one it denies prove the oracle answers truthfully.
- References: kernel/common security/selinux/selinuxfs.c (sel_write_access); system/sepolicy private/app_neverallows.te and the domain .te files for the expected answers.
- Applicability: carriers that can resolve selinux_check_access. On Android 10 and 11 the app_zygote carrier detaches the AVC netlink socket libselinux opens for these checks (external/selinux libselinux/src/avc.c) once they finish, because before Android 12 that zygote aborts every fork while its preload leaves a socket other than a named AF_UNIX one open (frameworks/base core/jni/fd_utils.cpp); the answers are unaffected.
- Visibility limits: an oracle that fails a control is untrusted; dirtyPolicyTrusted is the single rule consumers use. The first selinux_check_access makes libselinux map and read the status page, so the oracle runs only when the status page mapping signal below reads intact or unavailable, and is otherwise reported unavailable with the reason.
- Result states: allowed, denied, untrusted, unavailable.
- Interpretation: consumers report trusted answers at their rule's severity and untrusted ones at lower confidence.

### Policy reload and process context

- Observable signal: the policyload counter in /sys/fs/selinux/status, as the status page mapping signal's child read it, compared with the access oracle's sequence number, and this process's /proc/self/attr/current.
- Producing subsystem: selinuxfs's status page and the process's SELinux label.
- Mechanism: a policy reload after boot, as root tools do to inject rules, advances the policyload counter. The carrier never reads the status page itself: on a node whose open handler is hooked, read() makes selinuxfs dereference the bogus page in kernel mode (sel_read_handle_status) and mapping it kills the carrier.
- References: kernel/common security/selinux/selinuxfs.c (status node); kernel/common Documentation/filesystems/proc.rst (attr).
- Applicability: every release.
- Visibility limits: an odd sequence means the status page was mid-update and the read is inconclusive; a status page that was not read leaves the comparison unavailable.
- Result states: consistent, reloaded, status page faulted, inconclusive, unavailable.
- Interpretation: consumers treat a reload as supporting evidence. A faulted status page is reported here too, because it is the page this comparison reads.

### Status page mapping

- Observable signal: whether a disposable child of the app_zygote carrier can open /sys/fs/selinux/status, map one page of it read-only and read its header back.
- Producing subsystem: selinuxfs's status node, whose open handler stores the kernel's status page and whose mmap handler maps it, and the arm64 fault handler that decides how a faulting user read ends.
- Mechanism: stock open stores the status page's struct page in the file's private data and mmap maps it with remap_pfn_range(page_to_pfn(...)), so the read cannot fault. A hook that replaces the open handler and stores anything else makes mmap map a bogus frame, and the first read faults. The reported kill was SIGKILL with SI_KERNEL sent from do_mem_abort, which arm64 4.19 does only for fault classes handled by do_bad, such as an address size fault from a frame beyond the configured physical address range; SIGKILL leaves no tombstone and, with show_unhandled_signals off, no kernel log line. libselinux makes the same open, mmap and read on its first access check (selinux_check_access -> avc_open -> selinux_status_open), so the carrier would take the same kill; the child takes it instead and the carrier records it. The child reports each step to the carrier, the last one just before its first read, so a signal counts as a fault of the page only when it ends a child that had mapped it.
- References: kernel/common security/selinux/selinuxfs.c (sel_open_handle_status, sel_mmap_handle_status, sel_read_handle_status); kernel/common arch/arm64/mm/fault.c (fault_info, do_bad, do_mem_abort) and arch/arm64/kernel/traps.c (show_unhandled_signals); external/selinux libselinux/src/sestatus.c (selinux_status_open), checkAccess.c and avc.c; frameworks/base core/jni/com_android_internal_os_Zygote.cpp (SpecializeCommon resets SIGCHLD, so the carrier reaps its own child during preload). Discovery only for KernelSU Next kernel/feature/selinux_hide.c at a54e4fa4, whose open hook stores page_address() of its fake page; that is how the kill reported in issue 156 was traced.
- Applicability: app_zygote carriers on every release. The KernelSU Next hook applies to processes under seccomp with an app UID, which the carrier and its child are. Which signal ends the read depends on the kernel's memory layout: SIGKILL on the reported arm64 4.19 kernel, possibly SIGBUS or SIGSEGV on another.
- Visibility limits: a bogus frame that happens to be readable memory does not fault, so a hooked node can still read back intact. A child killed before it mapped the page leaves the outcome inconclusive, as do a fork, wait or seccomp failure and a child that has not finished after one second; that child is stopped, and left behind rather than waited for if it has not died 250 ms later.
- Result states: intact, faulted, unavailable (open or mmap failed), inconclusive.
- Interpretation: faulted means the status node gave this app a mapping stock selinuxfs never produces, which the policyload comparison reports as a finding. Only intact or unavailable lets libselinux's access checks run in the carrier, since libselinux falls back to netlink when it cannot map the page; faulted and inconclusive skip them, leaving the dirty policy oracle and the dyntransition self-check unavailable instead of killing the carrier.
