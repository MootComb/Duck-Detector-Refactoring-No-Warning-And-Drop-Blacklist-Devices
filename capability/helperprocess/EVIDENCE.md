# Helper process capability evidence record

Status: reviewed

The helper process capability runs probes in a separate helper process and in an isolated process, and returns their snapshots to the Mount, Native Root and Virtualization detectors. The evidence is the difference between process views.

## Signals

### Cross-process identity and mount view

- Observable signal: the helper's and isolated process's mount namespace, mount anchors, dex path and UID identity, and the per-process mount view scan.
- Producing subsystem: zygote's specialization of each process and the kernel's namespaces.
- Mechanism: zygote gives an isolated process its own UID and a fresh mount namespace; an app virtualization host or a root profile that changes the main process does not change the isolated one the same way. The mount view scan compares tables without the size= and nr_inodes= options of tmpfs, devtmpfs and rootfs: the kernel prints them only while they differ from half of the current RAM, so a change in total RAM after boot would split otherwise identical tables, such as the app data tmpfs zygote mounts without a size.
- References: frameworks/base core/jni/com_android_internal_os_Zygote.cpp (per-process UID and mount setup, MountAppDataTmpFs); kernel/common Documentation/filesystems/proc.rst (ns and mountinfo); kernel/common mm/shmem.c (shmem_show_options compares capacity with the current totalram_pages()).
- Applicability: every release that supports isolated services.
- Visibility limits: a helper that fails to bind or start leaves its snapshot unavailable. A binding the system stops before the helper connects, as it does to every service of the package when another of its processes fails to start, is bound once more, because nothing ran in the helper yet.
- Result states: collected, unavailable.
- Interpretation: consumers decide which drift is significant.

### Sacrificial syscall pack, honeypots and EGL

- Observable signal: the results of syscall, timing and trap honeypots run in a disposable process, and the EGL vendor and renderer.
- Producing subsystem: the kernel, the CPU and the GPU driver stack.
- Mechanism: hypervisors and translators change trap and timing behaviour, and emulators expose software renderers.
- References: bionic libc/SECCOMP_BLOCKLIST_APP.TXT and libc/SYSCALLS.TXT (which syscalls an app process may make); system/core debuggerd/include/debuggerd/handler.h (the SIGSYS handler every process inherits writes a tombstone). Discovery only for the honeypot thresholds and renderer strings.
- Applicability: assembly traps are ABI specific.
- Visibility limits: seccomp refuses syscalls the app filter lacks, such as openat2 and pidfd_open on Android 11, so the syscall pack runs in a disposable child whose SIGSYS handler exits instead of leaving a tombstone, and a refusal marks the pack blocked for the rest of the helper process.
- Result states: collected, blocked, unavailable.
- Interpretation: consumers treat these as corroboration.
