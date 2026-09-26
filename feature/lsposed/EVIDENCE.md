# LSPosed evidence record

Status: reviewed

The LSPosed detector asks whether an Xposed-style framework (LSPosed, EdXposed, LSPatch and similar) is active in this process or installed on the device. Runtime signals in this process are direct evidence; package and policy signals are corroboration.

## Signals

### Runtime classes, loaders and bridge state

- Observable signal: Xposed, libXposed and LSPosed classes reachable from app and boot class loaders, suspicious ClassLoader chains, and live XposedBridge fields.
- Producing subsystem: ART class loading in this process.
- Mechanism: the framework injects its bridge classes into the app's class loader hierarchy and keeps hook state in static fields.
- References: Discovery only: the class names, loader names and fields follow the LSPosed and Xposed APIs; their sources were not reviewed in this pass.
- Applicability: every release the frameworks support.
- Visibility limits: reflection on hidden fields can be blocked; frameworks can rename classes.
- Result states: detected, clean.
- Interpretation: live bridge state and injected classes are direct evidence and danger.

### Stacks, callbacks, binder bridge and logcat

- Observable signal: XposedBridge or LSPHooker frames in current and synthetic stacks, an uncaught exception handler that points to the framework, LSPosed bridge transactions on activity and serial services, framework log tags visible to the app, and framework Unix sockets, descriptors and environment variables in this process.
- Producing subsystem: ART stacks, the framework's binder bridge, and logd.
- Mechanism: hooked methods run through the framework's callbacks, and the framework serves its bridge over existing system service binders.
- References: Discovery only: the frame tokens, transaction codes and log tags follow LSPosed's observed behaviour.
- Applicability: every release; logcat shows other apps' logs only where logd allows.
- Visibility limits: binder probes depend on hidden API access; logcat usually shows only this app's entries.
- Result states: detected, clean, unavailable.
- Interpretation: framework frames and bridge answers are danger; log tags are supporting evidence.

### Zygote permission GIDs

- Observable signal: permissions granted to this app whose mapped supplementary GIDs are missing from /proc/self/status.
- Producing subsystem: zygote, which sets supplementary GIDs from the platform permission map.
- Mechanism: a framework that respawns or re-specializes the process can lose the GIDs zygote would have set.
- References: frameworks/base data/etc/platform.xml (permission to GID mapping, for example INTERNET to inet); kernel/common Documentation/filesystems/proc.rst (status Groups).
- Applicability: permissions with a mapped GID only.
- Visibility limits: none beyond reading this process's own status.
- Result states: mismatch, consistent.
- Interpretation: a missing GID for a granted permission is a warning.

### Dirty policy rules and native traces

- Observable signal: LSPosed-related allowed edges from the SELinux oracle, framework mappings in /proc/self/maps and keyword residue in readable heap regions.
- Producing subsystem: the loaded SELinux policy and this process's memory.
- Mechanism: LSPosed ships policy rules and maps its native libraries into hooked processes.
- References: capability/selinuxpolicy/EVIDENCE.md for the oracle; kernel/common Documentation/filesystems/proc.rst for maps. Discovery only for the LSPosed rule names and library names.
- Applicability: the maps and heap probes need libduckdetector.
- Visibility limits: an untrusted oracle is reported at lower confidence; unreadable maps reduce coverage.
- Result states: rule present, untrusted, detected, unavailable.
- Interpretation: a trusted LSPosed rule is danger, an untrusted one at most warning; maps hits are danger.

### Packages and module metadata

- Observable signal: installed framework and module manager packages, and xposedmodule metadata in installed apps.
- Producing subsystem: PackageManager.
- Mechanism: modules declare themselves through manifest metadata.
- References: frameworks/base core/java/android/content/pm/PackageManager.java; capability/packageinventory/EVIDENCE.md.
- Applicability: needs package visibility.
- Visibility limits: without QUERY_ALL_PACKAGES, filtering hides most packages, which is reported.
- Result states: found, clean, restricted.
- Interpretation: packages alone are softer residue than runtime signals.
