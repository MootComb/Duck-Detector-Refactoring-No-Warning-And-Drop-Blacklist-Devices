# Play Integrity Fix evidence record

Status: reviewed

The Play Integrity Fix detector asks whether a Play Integrity spoofing module left property or runtime residue in this device or process.

## Signals

### PIF residue properties

- Observable signal: persist.sys.pihooks, Pixel property overrides, spoofed device identity and security patch properties.
- Producing subsystem: init's property service, where the module or its companion writes these values.
- Mechanism: spoofing modules persist their configuration and overrides as properties.
- References: system/core init/property_service.cpp; bionic libc/include/sys/system_properties.h. Discovery only for the list of PIF property names.
- Applicability: every release.
- Visibility limits: property contexts the app may not read return empty.
- Result states: detected, clean.
- Interpretation: PIF control properties are danger; identity overrides are warning or danger by rule.

### Source consistency and runtime maps

- Observable signal: the same residue property through reflection, getprop, JVM and native libc, and PIF-related libraries in /proc/self/maps.
- Producing subsystem: bionic's property area and this process's address space.
- Mechanism: a module that hides its properties from one read path, or injects into the app, leaves disagreement or mappings.
- References: frameworks/base core/java/android/os/SystemProperties.java; kernel/common Documentation/filesystems/proc.rst (maps). Discovery only for the library name patterns.
- Applicability: every release.
- Visibility limits: getprop runs with this app's permissions.
- Result states: mismatch, detected, consistent, unavailable.
- Interpretation: disagreement and mappings are evidence of the module.
