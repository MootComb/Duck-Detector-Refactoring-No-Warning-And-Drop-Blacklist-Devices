# System properties capability evidence record

Status: reviewed

The system properties capability reads each property through several independent paths and snapshots the native property areas, for the Bootloader and System Properties detectors.

## Signals

### Multi-source property reads

- Observable signal: one property's value through android.os.SystemProperties, getprop, System.getProperty and __system_property_get.
- Producing subsystem: bionic's shared property areas, written by init's property service.
- Mechanism: all sources read the same property area on a genuine device, so a hook on one path shows as disagreement.
- References: bionic libc/include/sys/system_properties.h; frameworks/base core/java/android/os/SystemProperties.java; system/core init/property_service.cpp.
- Applicability: every release.
- Visibility limits: properties whose SELinux context the app may not read are empty in every source.
- Result states: consistent, mismatch, unreadable.
- Interpretation: consumers apply their own rules to the preferred value and the disagreement.

### Raw boot parameters and property areas

- Observable signal: androidboot.* values in /proc/cmdline and /proc/bootconfig, read-only property handles, and holes in /dev/__properties__.
- Producing subsystem: the bootloader's command line and bionic's property areas.
- Mechanism: init imports androidboot.* as ro.boot.*, so the raw and runtime values agree unless something rewrote one of them.
- References: system/core init/property_service.cpp (ProcessKernelCmdline and ProcessBootconfig); bionic libc/include/sys/system_properties.h. Discovery only for the property area hole heuristics.
- Applicability: bootconfig on Android 12 and later kernels.
- Visibility limits: /proc/cmdline and bootconfig are often unreadable for apps.
- Result states: read, unreadable.
- Interpretation: consumers compare the raw values with the runtime ones.
