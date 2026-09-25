# ADR 0005: Give native code units with owners, targets and include rules

- Status: Accepted
- Date: 2026-09-25

## Context

All native sources compiled into one CMake shared-library target with one flag set, so CMake expressed no ownership at all. Directories under `app/src/main/cpp` roughly matched detectors, but `selinux/` mixed a capability's context-validity probe with the SELinux feature's audit probe. Assembly lived under `asm/<abi>/` by architecture rather than by owner. Because the source root is the include directory, any file could include any other unit's header, whether with quotes or angle brackets, and nothing noticed.

The Kotlin side meanwhile gained strict module boundaries ([ADR 0001](./0001-gradle-module-boundaries.md)), and several JNI bridges moved into capability modules ([ADR 0004](./0004-shared-evidence-capabilities.md)). Without a native counterpart, native code could still couple units that Kotlin keeps apart, and a JNI export could end up in a unit its Kotlin owner does not control. AGENTS.md treats JNI as an architectural boundary and asks for narrow, feature-specific native implementations.

## Decision

1. A native unit is a directory under `app/src/main/cpp` with one owning Gradle module. [`native-boundaries.json`](../../.github/policies/native-boundaries.json) lists each unit's path, owner, CMake target and the units whose headers it may include. The longest matching path wins, so `mount/zygotenext` is a unit of its own inside `mount/`.
2. Directories were made single-owner first. The context-validity files moved to `selinuxpolicy/`, and the assembly moved to `tee/asm/<abi>/` and `virtualization/asm/arm64/`, the only callers of those routines. The ABI split is kept inside each unit.
3. Every unit compiles as a `duckdetector_<unit>` object library created by `duckdetector_native_unit`, which applies the flags, position-independent code and Release IPO that the single target used to apply. `libduckdetector.so` compiles no sources of its own and links every unit. `libmain.so`, which `zygote_next` loads without ART, is the standalone target of the `zygotenext` unit. It compiles its own copy of `common/` because it always uses hidden visibility.
4. A unit may include its own headers and those of the units in its `may_include` list, which is `common` for every unit. Anything else needs an include exception naming the exact header and a reason. Unused exceptions fail the check, so they cannot outlive their cause. The only exception lets `preload` include `virtualization/snapshot_builder.h`, because the startup capture must run the same snapshot collector as the runtime bridge.
5. `check-native-boundaries.py` verifies the following: every native file belongs to exactly one unit; quoted, angle-bracket and relative includes resolve within the allowed units; each unit's sources are compiled by its own target and by no other object target; the aggregate library links every unit; and every `Java_` export in a unit binds a Kotlin or Java declaration from the unit's owning module. It reuses the parsers of `check-jni-contracts.py` for the last rule. `test-native-boundaries.py` covers each rule with synthetic trees, and both run in the CI `contracts` job.

## Consequences

- A native file outside every unit, a new cross-unit include or a JNI export in the wrong unit fails CI with the file and line.
- The restructuring did not change the binaries. Normalized compile commands for all 426 source and ABI pairs match the single-target build in both Debug and RelWithDebInfo, and so do the defined dynamic symbols of both libraries on all four ABIs.
- Units can now receive unit-specific compile options or sanitizers without affecting the others.
- Release variants still use CMake's `RelWithDebInfo` configuration, so the Release-only flags do not reach shipped builds. This was preserved rather than fixed ([follow-ups](../architecture/follow-ups.md)).
- The label matching between `preload` and `virtualization` remains a text protocol until findings carry a typed kind ([follow-ups](../architecture/follow-ups.md)).
