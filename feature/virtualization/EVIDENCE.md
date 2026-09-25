# Virtualization evidence record

Status: reviewed

The Virtualization detector asks whether this app runs inside an emulator, a translated runtime or an app virtualization host. Capability-only signals, such as a hypervisor being available, are reported as information, not as evidence that this app is a guest.

## Signals

### Properties, build fields and guest services

- Observable signal: ro.kernel.qemu and QEMU guest properties, emulator hardware properties, generic build tokens, and qemud or VirtualizationService in ServiceManager.
- Producing subsystem: init's property service, Build, and ServiceManager.
- Mechanism: emulator images set guest properties and run guest services that physical devices do not.
- References: system/core init/property_service.cpp (how ro.* properties are set); frameworks/base core/java/android/os/SystemProperties.java. Discovery only for the emulator token catalogs.
- Applicability: every release; VirtualizationService exists on devices with pKVM regardless of whether this app is a guest.
- Visibility limits: ServiceManager lookups can fail; a failed lookup leaves the row partial.
- Result states: hits, info hits, clean, partial.
- Interpretation: direct guest properties and qemud are danger; capability-only services are info.

### Native bridge and translated execution

- Observable signal: ro.dalvik.vm.native.bridge, translated runtime libraries such as libhoudini and libndk_translation, and an ABI list that disagrees with Build.SUPPORTED_ABIS.
- Producing subsystem: ART's native bridge and zygote.
- Mechanism: a translated runtime loads a native bridge library named by that property.
- References: frameworks/base core/jni/AndroidRuntime.cpp (reads ro.dalvik.vm.native.bridge; "0" disables it) and core/jni/com_android_internal_os_Zygote.cpp (native bridge pre-initialization).
- Applicability: every release.
- Visibility limits: none beyond property readability.
- Result states: translated, clean.
- Interpretation: translation alone is a warning, since legitimate x86 devices also translate arm apps.

### Runtime artifacts, graphics and honeypots

- Observable signal: device nodes, maps, descriptors and mount anchors, the EGL renderer, and native, assembly and syscall honeypots run in sacrificial processes.
- Producing subsystem: the kernel, the GPU driver stack and the helper processes.
- Mechanism: emulators expose virtual devices and software renderers, and hypervisors change trap and timing behaviour.
- References: kernel/common Documentation/filesystems/proc.rst for maps and mountinfo; capability/helperprocess/EVIDENCE.md for the sacrificial processes. Discovery only for renderer strings and honeypot thresholds.
- Applicability: the assembly honeypots are ABI specific and report unsupported elsewhere.
- Visibility limits: a helper that fails to start leaves its checks unavailable.
- Result states: hits, warnings, clean, unavailable.
- Interpretation: an EGL renderer alone stays a warning; trap anomalies are corroboration.

### Cross-process and host app consistency

- Observable signal: differences between the main app, a helper and an isolated process in classpath, UID identity and mount view, and installed app virtualization hosts.
- Producing subsystem: zygote, PackageManager and the helper processes.
- Mechanism: app virtualization hosts run guest apps inside their own process and UID, which the isolated process does not inherit.
- References: frameworks/base core/jni/com_android_internal_os_Zygote.cpp (per-app UID and mount setup) and core/java/android/content/pm/PackageManager.java (package visibility); capability/helperprocess/EVIDENCE.md and capability/packageinventory/EVIDENCE.md.
- Applicability: every release; host apps are visible only with package visibility.
- Visibility limits: host apps found only by the native data directory stat may be missing when that check cannot run.
- Result states: drift, host apps, clean, unavailable.
- Interpretation: drift is danger or warning by kind; host apps alone are corroboration only.
