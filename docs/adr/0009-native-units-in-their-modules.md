# ADR 0009: Native units live in the modules that own them

- Status: Accepted
- Date: 2026-09-26
- Amends: [ADR 0005](./0005-native-unit-boundaries.md), unit layout

## Context

[ADR 0005](./0005-native-unit-boundaries.md) split the native code into units, each owned by one Kotlin module. The sources still sat in one tree: first in `:app`, then in `:sdk:runtime` once the SDK had to ship the libraries. That tree was far from the owning modules:

- The SU detector's C++ lived under `sdk/runtime/src/main/cpp/su/`, while its JNI bridge lived under `feature/su/data/`.
- Changing a detector's native sources meant editing the one central `CMakeLists.txt`.

## Decision

1. Each unit moves unchanged into its owner, as `<module>/src/main/cpp/<unit path>`. The union of those directories forms the same native tree as before: every file keeps its native path, for example `su/native_bridge.cpp`.
2. Each unit directory has a `CMakeLists.txt` that lists the unit's sources and declares its target, including any ABI-specific assembly.
3. `sdk/runtime/src/main/cpp/CMakeLists.txt` only aggregates. Its `DUCKDETECTOR_NATIVE_UNITS` registry names every object unit with its owning module, in link order. From that registry it:
   - adds each unit's directory;
   - makes every owner's `src/main/cpp` an include directory, so `#include "common/payload_codec.h"` resolves as before;
   - links the units into `libduckdetector.so` in registry order.
4. Native boundary policy schema 2 drops the single source root. `check-native-boundaries.py` enforces that:
   - every native file belongs to the unit with the longest matching native path and lives in the module that owns that unit;
   - no two modules provide the same native path;
   - every object unit is registered under its owner.

   It also reads the unit CMake files, and keeps checking includes, compiled sources and JNI owners.

## Consequences

- A detector's Kotlin, JNI bridge and C++ sit in one feature directory. Changing its native sources touches only that directory.
- A new native unit adds its directory, one registry line and one `native-boundaries.json` entry.
- Link order, compile flags and include resolution are unchanged. For every ABI, the stripped `libduckdetector.so` and `libmain.so` of debug and release builds match the previous build in every section except the build-id note, and in their dynamic symbol tables.
- Compile commands now name the new source paths and one include directory per owning module, so debug information refers to the new locations.
