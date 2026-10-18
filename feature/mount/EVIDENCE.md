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
- Interpretation: explicit root-managed path/source markers are danger. Writable system, overlay and loop-backed system mounts are review warnings because AOSP development remounts can legitimately produce them. A source pathname alone cannot establish dm-verity state; non-root mount roots and SELinux context options are informational. The legacy bypass/bind/context/namespace-anomaly flags are retained for payload compatibility but are no longer asserted from these properties.

### Mount ID discontinuities

- Observable signal: nonconsecutive IDs in adjacent mountinfo records immediately after `/apex/com.android.art` or before `/data_mirror`, including descending IDs. Retain both paths and IDs; do not count absent mounts from adjacent rows.
- Producing subsystem: the kernel mount allocator and this process's mount namespace.
- Mechanism: the allocator is global and releases IDs for reuse, while procfs iterates the selected namespace's mount list. Neither allocation nor record adjacency establishes a consecutive sequence for one process. A number between adjacent rows can also occur elsewhere in the same file.
- References: primary sources pinned to inspected revisions:
  - [ACK android14-5.15 `fs/namespace.c`](https://android.googlesource.com/kernel/common/+/9debaec240781879fbb65b9303f7cfc3e1d96c02/fs/namespace.c): `mnt_id_ida`, `mnt_alloc_id`, `mnt_free_id`.
  - [ACK android14-6.1 `fs/namespace.c`](https://android.googlesource.com/kernel/common/+/48e3cd973485465613da6d71fa17139773546573/fs/namespace.c): the same allocator, plus `mnt_list_next`, `m_start`, `m_next`, and `copy_mnt_ns`.
  - [ACK android15-6.6 `fs/namespace.c`](https://android.googlesource.com/kernel/common/+/150617c4d667a241e52441e855befac0c5d6702b/fs/namespace.c): the same allocation/release semantics.
  - [ACK 6.1 procfs documentation, section 3.5](https://android.googlesource.com/kernel/common/+/48e3cd973485465613da6d71fa17139773546573/Documentation/filesystems/proc.rst): IDs identify mounts and may be reused after unmount.
  - [ACK 6.1 `fs/proc_namespace.c`](https://android.googlesource.com/kernel/common/+/48e3cd973485465613da6d71fa17139773546573/fs/proc_namespace.c): `mounts_open_common` selects the task namespace and root; `show_mountinfo` emits mount IDs.
  - [Android application sandbox](https://source.android.com/docs/security/app-sandbox) and [Android 14 Zygote](https://android.googlesource.com/platform/frameworks/base/+/299fe6f5d6fc6f1af7c3411dcf4e5efdf7217368/core/jni/com_android_internal_os_Zygote.cpp): `isolateAppData` mounts tmpfs over app data parents and binds app directories from `/data_mirror`; this is legitimate platform behavior.
- Applicability: the inspected ACK branches and Android 14 source establish counterexamples to a universal continuity assumption. They do not identify an OEM device's exact sequence of allocations, releases, namespace cloning, or mount changes. These sources provide no consecutive-ID security contract or justified gap threshold.
- Result states: informational observation or no local observation. Runtime separately reports mountinfo availability. The preload has no per-probe read/parse availability field, so an absent observation there does not establish successful collection. The shared routine only consumes parsed entries.
- Interpretation: INFO only, regardless of interval size or repeated startup/runtime captures. These captures are not independent corroboration. Historical field and finding IDs containing `loophole` are retained for payload compatibility; the displayed label is `Mount ID discontinuity`. Legacy DANGER records are also interpreted as INFO.
- Visibility limits: discontinuities cannot establish root, hiding, or a clean device. A contiguous list does not exclude hidden mounts. The origin of specific IDs requires a contemporaneous complete namespace snapshot and device/build/kernel context; a screenshot is insufficient.
- Validation: `python3 core/native/src/test/python/test_mount_id_observation.py` checks the shared native policy, including 1/2/3/8/16 intervals, IDs visible elsewhere, descending/reused IDs, integer boundaries, and absent anchors. Mount repository, preload result, and card mapper unit tests verify that observations and denied coverage do not raise risk, while direct root evidence remains actionable; statx comparison limitations are covered below. These are synthetic regressions, not captured stock/OEM device validation.

### Cross-view consistency

- Observable signal: peer group gaps, minor device gaps, statx mount IDs and mount-root attributes that disagree with mountinfo, and namespace identity versus init.
- Producing subsystem: the kernel's mount ID allocator, statx and namespace links.
- Mechanism: statx resolves the active mount after pathname/symlink lookup; mountinfo lists namespace records, including covered mounts. These are separate, non-atomic captures. A literal target row is not an expected statx mount ID. Peer/minor IDs and proc inode timestamps describe allocation or inode state, not hiding.
- References: kernel/common Documentation/filesystems/proc.rst (mountinfo mount IDs and propagation); kernel/common include/uapi/linux/stat.h (STATX_MNT_ID and STATX_ATTR_MOUNT_ROOT).
- Applicability: statx needs a kernel that fills the mount ID fields; /proc/1/ns/mnt is readable only where SELinux allows it.
- Visibility limits: a different app/init mount namespace is compatible with ordinary Zygote isolation. Namespace identity or access denial alone does not establish root.
- Result states: anomaly, mount root, review, clean, unsupported, unavailable.
- Interpretation: non-atomic statx/filesystem differences, the VFS mount-root attribute, root propagation and namespace identity are informational. A visible statx ID elsewhere in mountinfo is accepted without a literal-target comparison. Missing returned mount-ID fields are reported as unsupported/limited coverage rather than a successful clean cross-check. No mount ancestry or hiding claim is derived from relative reusable IDs.

### Maps, Zygote Next and isolated process mount views

- Observable signal: Zygisk, Riru and Magisk-hidden library paths in /proc/self/maps, the Zygote Next mount view compared with the main process, and the mount views of other processes collected by the isolated helper.
- Producing subsystem: this process's address space, zygote's mount namespace setup, and the helper process.
- Mechanism: a root solution that isolates mounts per app leaves the app's view different from zygote's and from other processes'.
- References: kernel/common Documentation/filesystems/proc.rst (maps, mountinfo and ns); frameworks/base core/jni/com_android_internal_os_Zygote.cpp; capability/helperprocess/EVIDENCE.md.
- Applicability: every release; the isolated helper must start.
- Visibility limits: other processes' mount views are visible only where procfs allows.
- Result states: hits, drift, clean, unavailable.
- Interpretation: explicit root-managed records or injection library path markers retain their finding severity. Namespace layout/reference-signature differences are informational coverage observations. Short words or substrings in unrelated source names, paths or options do not identify a root manager; Kotlin and native collectors match structured fields, exact source names, and bounded root paths.

### Paths, startup preload and shell tmp

- Observable signal: busybox and hybrid mount paths, the mount view captured by the NativeActivity before the activity it launches, and whether /data/local/tmp is hidden or remapped.
- Producing subsystem: the filesystem and the early launch capture.
- Mechanism: hiding applied after launch leaves differences between the early and later views.
- References: capability/earlypreload/EVIDENCE.md for the capture; system/core rootdir/init.rc for /data/local/tmp. Discovery only for busybox and hybrid mount paths.
- Applicability: the preload needs the transparent launcher; SDK hosts without it report it unavailable.
- Visibility limits: denied path checks and inaccessible init namespace links describe partial coverage. They are informational regardless of their count and do not corroborate root or mount hiding.
- Result states: hits, signals, busybox, clean, partial, unavailable.
- Interpretation: specific accessible root data artifacts and explicit root paths in mountinfo roots retain danger. Generic BusyBox outside root-specific directories, kernel overlayfs availability, vendor path candidates, debug ramdisk markers and proc inode timestamps are informational. A shell-tmp dedicated mount is a review warning; denial, absence under an accessible parent, and non-atomic Java/native differences are informational, not evidence of concealment. Shell-tmp stat queries follow symlinks consistently with Java File.

## Applicability and counterexamples behind classification

- [ACK 6.1 `fs/stat.c`](https://android.googlesource.com/kernel/common/+/48e3cd973485465613da6d71fa17139773546573/fs/stat.c), `vfs_statx`: mount IDs come from the resolved VFS mount, and `STATX_ATTR_MOUNT_ROOT` means the resolved dentry equals that mount's root. Neither field is an anomaly by itself. Symlinks, stacked/covered mounts and intervening mount operations defeat comparisons with one literal mountpoint row.
- [ACK 6.1 `fs/super.c`](https://android.googlesource.com/kernel/common/+/48e3cd973485465613da6d71fa17139773546573/fs/super.c), `unnamed_dev_ida`, `get_anon_bdev`, `free_anon_bdev`, and `fs/namespace.c`'s group allocator establish globally allocated/reusable device and peer identifiers. Their absence from this process's view is not hidden-mount evidence.
- [ACK 6.1 `fs/proc/base.c`](https://android.googlesource.com/kernel/common/+/48e3cd973485465613da6d71fa17139773546573/fs/proc/base.c), `proc_pid_make_inode`, initializes proc inode timestamps at inode creation. [Namespace symlink lookup](https://android.googlesource.com/kernel/common/+/48e3cd973485465613da6d71fa17139773546573/fs/proc/namespaces.c) uses that inode factory. These are not mount-event timestamps; earlier lookup and realtime clock changes are counterexamples to an age-based hiding inference.
- [AOSP Android 14 overlayfs remount documentation](https://android.googlesource.com/platform/system/core/+/refs/tags/android-14.0.0_r1/fs_mgr/README.overlayfs.md) describes writable/overlay system mounts on development builds. This justifies review of the observed mount configuration, not attribution to root tooling.
- [AOSP VTS debug-ramdisk guidance](https://source.android.com/docs/core/tests/vts/vts-on-gsi) and [Android 14 init debug-ramdisk paths](https://android.googlesource.com/platform/system/core/+/refs/tags/android-14.0.0_r1/init/debug_ramdisk.h) describe platform debugging artifacts such as `adb_debug.prop` and userdebug policy files. Their presence does not identify third-party root tooling.
- [Android SELinux context guidance](https://source.android.com/docs/security/features/selinux/implement#context-files) describes legitimate mount context options. Their presence alone does not establish a policy override by root tooling.
- [Android 14 init.rc](https://android.googlesource.com/platform/system/core/+/refs/tags/android-14.0.0_r1/rootdir/init.rc) creates `/data/local/tmp`; creation policy does not guarantee visibility to every unprivileged app or prohibit OEM-specific mount layouts. [Android 14 Java File](https://android.googlesource.com/platform/libcore/+/refs/tags/android-14.0.0_r1/ojluni/src/main/java/java/io/File.java) makes failed existence/read queries observational, not proof of hiding. Sequential queries are not an atomic consistency check.

Collection reads to EOF, retries EINTR, rejects over-limit/read-failed captures instead of parsing a prefix, preserves mountinfo record order, and rejects malformed or overflowing device numbers in both parsers. A missing main mount-table capture produces limited coverage, not an all-clear result.

Validation: `python3 feature/mount/data/src/test/python/test_mount_evidence_host_native.py` compiles and executes the actual native table, filesystem, parser, and bounded-reader implementations with injected platform I/O. Fixtures include ordinary block-source paths, development overlays/loop mounts, exact versus similar root markers, symlink-resolved IDs, stacked mounts, non-atomic ID changes, absent statx masks/errors, root-overlay coverage, short reads/EINTR/truncation, and malformed numeric fields. Kotlin repository, preload, shell-tmp and card tests verify classification propagation and retention of direct root evidence. No physical device was connected; these fixtures do not certify an OEM baseline or quantify false-positive/false-negative rates. Name/path fingerprints remain heuristic and can be hidden or imitated. Generic root-managed mount artifacts use the `ROOT_MOUNT_ARTIFACT` flag without attributing them to Magisk; existing specific manager flags remain separate.
