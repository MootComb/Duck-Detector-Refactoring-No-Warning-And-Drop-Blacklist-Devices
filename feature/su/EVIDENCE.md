# SU evidence record

Status: reviewed

The SU detector asks whether an su binary, a root daemon or a root SELinux context is visible from this app. It reports what it can see; most root solutions hide these from ordinary apps, so a clean result is weak evidence.

## Signals

### su binaries and root daemons

- Observable signal: su binaries in fixed paths and on PATH, `which su`, and KernelSU, Magisk and APatch daemons.
- Producing subsystem: the filesystem as seen through DAC and SELinux.
- Mechanism: classic root solutions install su in system paths; modern ones keep their files under /data/adb.
- References: system/core rootdir/init.rc (AOSP never creates /data/adb); system/sepolicy private/file_contexts (/data/adb is adb_data_file, which no app domain may search).
- Applicability: every release.
- Visibility limits: paths under /data/adb are not observable where the directory exists; PathStat reports them apart from absent paths, and `which` runs with this app's own permissions.
- Result states: found, clean, partial.
- Interpretation: a visible binary or daemon is danger; unobservable paths reduce coverage to SUPPORT.

### Process context and suspicious processes

- Observable signal: this process's SELinux context and processes whose context or name matches root tooling.
- Producing subsystem: procfs and SELinux process labels.
- Mechanism: a process running in a root or su domain, or seeing su-domain processes, has root tooling in its environment.
- References: kernel/common Documentation/filesystems/proc.rst (/proc/<pid>/attr and status). Discovery only for the list of suspicious context and process tokens.
- Applicability: every release; hidepid and SELinux usually deny other UIDs' /proc entries.
- Visibility limits: denied reads are counted and treated as visibility evidence only.
- Result states: root context, normal, fallback context, unavailable.
- Interpretation: an abnormal own context or a suspicious process is danger; native unavailability reduces coverage.
