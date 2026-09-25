# Package inventory capability evidence record

Status: reviewed

The package inventory capability lists installed packages and states how much of the device this app can see, for the Custom ROM, Dangerous Apps, LSPosed, Native Root and Virtualization detectors.

## Signals

### Installed package inventory and visibility

- Observable signal: the packages PackageManager returns, and whether this app's own package and a known system package are among them.
- Producing subsystem: PackageManager and its package visibility filtering.
- Mechanism: without QUERY_ALL_PACKAGES or matching queries, filtering hides most packages; the inventory records which case applies.
- References: frameworks/base core/java/android/content/pm/PackageManager.java.
- Applicability: filtering applies to apps targeting Android 11 and later.
- Visibility limits: the SDK declares no permissions, so the host decides visibility.
- Result states: full, restricted, unknown, unavailable.
- Interpretation: consumers do not read absence from a restricted inventory as absence on the device.

### Data directory stat

- Observable signal: whether /data/data/<package> exists, through raw stat syscalls.
- Producing subsystem: the filesystem under /data/data.
- Mechanism: stat on another app's data directory fails with ENOENT when it is absent and with another error when it exists but is denied.
- References: system/sepolicy private/seapp_contexts (app data directories are labelled app_data_file per app); kernel/common include/uapi/linux/stat.h.
- Applicability: every release.
- Visibility limits: the stat needs libduckdetector; when it cannot run, the capability returns no answer rather than an empty set.
- Result states: present set, no answer.
- Interpretation: consumers add the method only to packages it found, and note when it did not run.
