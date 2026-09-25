# System Properties evidence record

Status: reviewed

The System Properties detector asks whether security-relevant properties describe a debug, unlocked or modified build, and whether property sources disagree in a way that suggests rewriting.

## Signals

### Security property catalog

- Observable signal: build type and tags, debuggable and secure flags, encryption state, OEM unlock state and custom ROM version properties.
- Producing subsystem: init's property service and the build's property files.
- Mechanism: user builds set fixed values for these properties; debug builds, unlocked devices and custom ROMs differ.
- References: system/core init/property_service.cpp; frameworks/base services/core/java/com/android/server/pdb/PersistentDataBlockService.java (sets sys.oem_unlock_allowed at android-15.0.0_r1, no longer at android-16.0.0_r1).
- Applicability: sys.oem_unlock_allowed is expected only through Android 15; any value from Android 16 was written by something other than AOSP.
- Visibility limits: properties whose context apps may not read return empty.
- Result states: danger, warning, info, clean.
- Interpretation: each rule's severity reflects what the value shows; a custom ROM property is a finding about the build.

### Source consistency

- Observable signal: the same property read through android.os.SystemProperties, getprop, System.getProperty and native __system_property_get.
- Producing subsystem: bionic's property area, the framework wrapper, and the getprop tool.
- Mechanism: a module that hooks one read path, or resets a property after boot, leaves sources in disagreement.
- References: bionic libc/include/sys/system_properties.h; frameworks/base core/java/android/os/SystemProperties.java; capability/systemproperties/EVIDENCE.md.
- Applicability: every release.
- Visibility limits: getprop runs with this app's own permissions.
- Result states: mismatch, consistent, unavailable.
- Interpretation: a disagreement is evidence of rewriting.

### Raw boot parameters and property area layout

- Observable signal: androidboot.* in /proc/cmdline and /proc/bootconfig, and holes in the /dev/__properties__ areas.
- Producing subsystem: the bootloader's command line and bionic's property areas.
- Mechanism: init imports androidboot.* as ro.boot.*; resetprop-style tools rewrite property areas and can leave holes.
- References: system/core init/property_service.cpp (bootconfig and cmdline import); bionic libc/include/sys/system_properties.h. Discovery only for the property area hole heuristics.
- Applicability: bootconfig on Android 12 and later kernels.
- Visibility limits: /proc/cmdline and bootconfig are often unreadable for apps.
- Result states: mismatch, hole found, consistent, unavailable.
- Interpretation: holes and raw-versus-runtime mismatches are danger or warning by rule.
