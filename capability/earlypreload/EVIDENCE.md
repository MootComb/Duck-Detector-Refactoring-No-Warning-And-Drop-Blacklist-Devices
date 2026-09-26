# Early preload capability evidence record

Status: reviewed

The early preload capability captures mount and virtualization evidence in the transparent NativeActivity before the activity it launches starts, and hands it to the Mount and Virtualization detectors. Its value is timing: hiding that is applied later in the process's life has not happened yet.

## Signals

### Early mount view

- Observable signal: mountinfo and mntent state at launch, including mount ID gaps, peer group gaps, minor device gaps and futile hide markers.
- Producing subsystem: the kernel's mount tables for the app's namespace, read before Java code runs.
- Mechanism: a hiding module that unmounts or rewrites entries after launch leaves the early view different from the later one.
- References: kernel/common Documentation/filesystems/proc.rst section 3.5 (mountinfo mount IDs, propagation and peer groups).
- Applicability: only when the app starts through the NativeActivity launcher; SDK hosts without it report the capture unavailable.
- Visibility limits: a capture older than the current process context is marked stale.
- Result states: captured, stale, not run.
- Interpretation: consumers merge the early findings with their runtime scan.

### Early virtualization view

- Observable signal: emulator properties, device nodes and translation markers at launch.
- Producing subsystem: init's property service and the kernel's device nodes.
- Mechanism: the same probes as the Virtualization detector run before a host framework can adjust the process.
- References: system/core init/property_service.cpp; frameworks/base core/jni/AndroidRuntime.cpp (native bridge property).
- Applicability: as for the early mount view.
- Visibility limits: the preload matches finding labels produced by the virtualization native unit, a text protocol recorded in docs/architecture/follow-ups.md.
- Result states: captured, stale, not run.
- Interpretation: consumers compare the early and runtime views.
