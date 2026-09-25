# Helper process capability evidence record

Status: reviewed

The helper process capability runs probes in a separate helper process and in an isolated process, and returns their snapshots to the Mount, Native Root and Virtualization detectors. The evidence is the difference between process views.

## Signals

### Cross-process identity and mount view

- Observable signal: the helper's and isolated process's mount namespace, mount anchors, dex path and UID identity, and the per-process mount view scan.
- Producing subsystem: zygote's specialization of each process and the kernel's namespaces.
- Mechanism: zygote gives an isolated process its own UID and a fresh mount namespace; an app virtualization host or a root profile that changes the main process does not change the isolated one the same way.
- References: frameworks/base core/jni/com_android_internal_os_Zygote.cpp (per-process UID and mount setup); kernel/common Documentation/filesystems/proc.rst (ns and mountinfo).
- Applicability: every release that supports isolated services.
- Visibility limits: a helper that fails to bind or start leaves its snapshot unavailable.
- Result states: collected, unavailable.
- Interpretation: consumers decide which drift is significant.

### Sacrificial syscall pack, honeypots and EGL

- Observable signal: the results of syscall, timing and trap honeypots run in a disposable process, and the EGL vendor and renderer.
- Producing subsystem: the kernel, the CPU and the GPU driver stack.
- Mechanism: hypervisors and translators change trap and timing behaviour, and emulators expose software renderers.
- References: bionic libc/SECCOMP_BLOCKLIST_APP.TXT (which syscalls an app process may make). Discovery only for the honeypot thresholds and renderer strings.
- Applicability: assembly traps are ABI specific.
- Visibility limits: seccomp kills the sacrificial process on blocked syscalls, which is why it is disposable.
- Result states: collected, blocked, unavailable.
- Interpretation: consumers treat these as corroboration.
