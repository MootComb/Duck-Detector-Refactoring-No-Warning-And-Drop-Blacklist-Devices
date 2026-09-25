# SELinux evidence record

Status: reviewed

The SELinux detector asks whether SELinux is enforcing for this app, whether the loaded policy grants rules stock policy denies, and whether audit output looks rewritten. An enforcing, clean result means these checks saw nothing wrong, not that the policy is stock.

## Signals

### Enforcement status

- Observable signal: /sys/fs/selinux/enforce, getenforce, the selinuxfs mount and this process's context in /proc/self/attr/current.
- Producing subsystem: the kernel's SELinux LSM and selinuxfs.
- Mechanism: selinuxfs exposes the enforce node to all readers; a denied read while the domain is enforcing, or a labelled context, bound what the mode can be.
- References: kernel/common security/selinux/selinuxfs.c (enforce node mode) and security/selinux/avc.c (avc_denied only denies when enforcing); system/sepolicy private/domain.te (every domain may search selinuxfs and getattr its files); Android CDD 9.7 (global enforcing mode is required).
- Applicability: every supported release.
- Visibility limits: some devices deny reading enforce; a denied read proves enforcing only through the paradox rule, and a labelled context proves SELinux is enabled, not enforcing.
- Result states: enforcing, enforcing (paradox), permissive, disabled, not observable, unknown.
- Interpretation: permissive or disabled are compatibility departures reported as danger; an unresolved mode stays unknown rather than defaulting to enforcing.

### Dirty policy rules

- Observable signal: whether the loaded policy allows edges stock policy denies, such as untrusted_app to magisk binder call or system_server execmem.
- Producing subsystem: the loaded SELinux policy, queried through an app_zygote access oracle.
- Mechanism: the capability asks security_compute_av style questions from app_zygote, with a control edge stock policy allows and one it denies to prove the oracle answers.
- References: system/sepolicy private/app_neverallows.te and the domain .te files for the stock expectations; capability/selinuxpolicy/EVIDENCE.md for the oracle.
- Applicability: Android releases whose app_zygote can reach the oracle; see the capability record.
- Visibility limits: an oracle that fails its own controls is untrusted; its answers are shown at lower confidence.
- Result states: rule present, not observed, untrusted oracle, unavailable.
- Interpretation: a trusted oracle's allowed edge is danger or a policy observation, as each rule's text says; untrusted answers never exceed warning.

### Audit integrity

- Observable signal: whether a controlled AVC denial appears in app-readable auditd logs, whether allow or rewrite markers appear, and auditpatch module residue.
- Producing subsystem: logd's audit buffer and libselinux's callback in this process.
- Mechanism: a module that rewrites logd's audit output leaves the controlled denial missing, altered or tagged.
- References: system/sepolicy private/file_contexts (/data/adb is adb_data_file, not searchable by apps). Discovery only for the ZN-AuditPatch residue paths and log markers.
- Applicability: devices where the app can read its own audit events.
- Visibility limits: AOSP does not guarantee that apps see matching audit events; residue under /data/adb is not observable from apps.
- Result states: clear, residue, exposed, tampered, inconclusive; residue rows can be not observable.
- Interpretation: tampering is warning or danger; absence of residue or events is inconclusive.

### Policy analysis

- Observable signal: the policy version, dangerous types and permissive domains visible through selinuxfs.
- Producing subsystem: the loaded policy's exported metadata.
- Mechanism: a policy version below the release's minimum, root-tool types or permissive domains indicate a modified or debug policy.
- References: kernel/common security/selinux/selinuxfs.c for the exported nodes. Discovery only for the list of root-tool types.
- Applicability: readable only where selinuxfs grants the app those nodes.
- Visibility limits: unreadable nodes leave the analysis partial.
- Result states: strong, minor drift, review, weak, unreadable.
- Interpretation: permissive domains and dangerous types are warning or danger; unreadable fields are support.

## Known gaps

- The policy notes pick their severity by matching the note text; see docs/architecture/follow-ups.md.
