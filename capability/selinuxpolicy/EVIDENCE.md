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
- Visibility limits: a carrier that cannot start leaves the snapshot unavailable.
- Result states: valid, invalid, unavailable.
- Interpretation: consumers decide which valid contexts are evidence.

### Dirty policy oracle

- Observable signal: allowed or denied answers for access edges stock policy denies.
- Producing subsystem: the loaded policy, through libselinux's selinux_check_access and selinuxfs's access node.
- Mechanism: the oracle computes the access vector for an edge; a control edge stock policy allows and one it denies prove the oracle answers truthfully.
- References: kernel/common security/selinux/selinuxfs.c (sel_write_access); system/sepolicy private/app_neverallows.te and the domain .te files for the expected answers.
- Applicability: carriers that can resolve selinux_check_access.
- Visibility limits: an oracle that fails a control is untrusted; dirtyPolicyTrusted is the single rule consumers use.
- Result states: allowed, denied, untrusted, unavailable.
- Interpretation: consumers report trusted answers at their rule's severity and untrusted ones at lower confidence.

### Policy reload and process context

- Observable signal: the policyload counter in /sys/fs/selinux/status compared with the access oracle's sequence number, and this process's /proc/self/attr/current.
- Producing subsystem: selinuxfs's status page and the process's SELinux label.
- Mechanism: a policy reload after boot, as root tools do to inject rules, advances the policyload counter.
- References: kernel/common security/selinux/selinuxfs.c (status node); kernel/common Documentation/filesystems/proc.rst (attr).
- Applicability: every release.
- Visibility limits: an odd sequence means the status page was mid-update and the read is inconclusive.
- Result states: consistent, reloaded, inconclusive, unavailable.
- Interpretation: consumers treat a reload as supporting evidence.
