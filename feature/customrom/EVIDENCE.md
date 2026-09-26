# Custom ROM evidence record

Status: reviewed

The Custom ROM detector asks whether this build is a community or modified ROM rather than the vendor's release. A custom ROM is a modification, not by itself root or compromise.

## Signals

### ROM properties and build fields

- Observable signal: ROM-specific properties such as ro.lineage.version, ROM tokens in Build fields, and ROM framework classes reachable by reflection.
- Producing subsystem: init's property service, which loads the build's property files, and the framework's Build class.
- Mechanism: community ROMs set their own version properties and ship their own framework classes.
- References: system/core init/property_service.cpp (build properties become ro.* values). Discovery only for the list of ROM property and class names.
- Applicability: every release.
- Visibility limits: a ROM can omit or rename its markers.
- Result states: detected, clean.
- Interpretation: a ROM marker is a finding about the build, not about root.

### Bootloader lock state

- Observable signal: ro.boot.flash.locked.
- Producing subsystem: the bootloader, through init.
- Mechanism: init copies androidboot.flash.locked from the kernel command line or bootconfig into ro.boot.flash.locked.
- References: system/core init/property_service.cpp (androidboot.* to ro.boot.* import).
- Applicability: bootloaders are not required to pass the value, so it can be empty.
- Visibility limits: an empty or unreadable value says nothing about the lock state.
- Result states: unlocked, not observed.
- Interpretation: only an explicit unlocked value is a finding.

### ROM services, packages and native residue

- Observable signal: ROM-specific system services, installed ROM packages, ROM libraries in /proc/self/maps, ROM files, policy files and native symbols.
- Producing subsystem: ServiceManager, PackageManager, and the filesystem.
- Mechanism: ROMs register their own services and install their own packages and libraries.
- References: frameworks/base core/java/android/content/pm/PackageManager.java (package visibility); kernel/common Documentation/filesystems/proc.rst (maps). Discovery only for the service, package and file catalogs.
- Applicability: every release; Pixel-only service checks run only on Pixel builds.
- Visibility limits: ServiceManager lookups can fail and package visibility can be restricted; both reduce coverage instead of reading clean.
- Result states: detected, clean, unavailable.
- Interpretation: residue corroborates the property markers; a failed service scan reports reduced coverage.
