# Mount evidence record

Status: reviewed

The Mount detector asks whether this app's mount view shows systemless root mounts, writable or overlaid system partitions, or hiding that leaves inconsistencies between kernel views. Findings describe this process's mount namespace.

## Signals

### Mount tables

- Observable signal: /proc/self/mounts and /proc/self/mountinfo entries for Magisk paths, writable system partitions, overlays, loop devices and dm-verity bypass patterns.
- Producing subsystem: the kernel's mount tables for this process's namespace.
- Mechanism: systemless root bind-mounts or overlays module files over system paths, which the mount tables list.
- References: kernel/common Documentation/filesystems/proc.rst section 3.5 (mountinfo fields, mount IDs, propagation).
- Applicability: every release; hiding modules unmount their entries from the app's namespace.
- Visibility limits: a namespace that hides the mounts leaves only indirect inconsistencies.
- Result states: hits, clean, unavailable.
- Interpretation: root mounts and writable system partitions are danger.

### Cross-view consistency

- Observable signal: mount ID gaps, peer group gaps, minor device gaps, statx mount IDs and mount-root attributes that disagree with mountinfo, and namespace identity versus init.
- Producing subsystem: the kernel's mount ID allocator, statx and namespace links.
- Mechanism: unmounting hidden entries leaves gaps and contradictions between independently exposed views.
- References: kernel/common Documentation/filesystems/proc.rst (mountinfo mount IDs and propagation); statx STATX_MNT_ID and STATX_ATTR_MOUNT_ROOT from upstream Linux (kernel.org man pages).
- Applicability: statx needs a kernel that fills the mount ID fields; /proc/1/ns/mnt is readable only where SELinux allows it.
- Visibility limits: an app shares init's namespace only when zygote isolation failed, so a different namespace is expected.
- Result states: anomaly, mount root, review, clean, unsupported, unavailable.
- Interpretation: contradictions between kernel views are danger; a mount-root attribute on a system subdirectory is a warning.

### Paths, startup preload and shell tmp

- Observable signal: busybox and hybrid mount paths, the mount view captured by the NativeActivity before MainActivity, and whether /data/local/tmp is hidden or remapped.
- Producing subsystem: the filesystem and the early launch capture.
- Mechanism: hiding applied after launch leaves differences between the early and later views.
- References: capability/earlypreload/EVIDENCE.md for the capture; system/core rootdir/init.rc for /data/local/tmp. Discovery only for busybox and hybrid mount paths.
- Applicability: the preload needs the transparent launcher; SDK hosts without it report it unavailable.
- Visibility limits: denied path checks are counted, not read as absent.
- Result states: hits, signals, busybox, clean, partial, unavailable.
- Interpretation: path and preload hits follow their finding severity; busybox alone is a warning.
