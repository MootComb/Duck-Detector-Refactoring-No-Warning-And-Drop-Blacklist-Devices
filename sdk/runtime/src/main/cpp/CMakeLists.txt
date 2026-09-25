cmake_minimum_required(VERSION 4.1.2)
project("duckdetector" LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported)

# Each native unit is an object library linked into libduckdetector.so. Its owning Kotlin module
# and the units whose headers it may include are declared in
# .github/policies/native-boundaries.json and checked by check-native-boundaries.py.
function(duckdetector_native_unit target)
    add_library(${target} OBJECT ${ARGN})
    set_property(TARGET ${target} PROPERTY POSITION_INDEPENDENT_CODE ON)
    if(ipo_supported)
        set_property(TARGET ${target} PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    endif()
    # Warnings stay warnings rather than errors: the probes deliberately do unusual things with
    # syscalls and raw memory, so a blanket -Werror would block builds on diagnostics that need
    # to be judged case by case. Surfacing them is the point.
    target_compile_options(${target} PRIVATE
        $<$<COMPILE_LANGUAGE:C,CXX>:-Wall -Wextra>
        $<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:C>>:-O2 -ffunction-sections -fdata-sections -fvisibility=hidden>
        $<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:CXX>>:-O2 -ffunction-sections -fdata-sections -fvisibility=hidden -fvisibility-inlines-hidden>
    )
    target_include_directories(${target} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
endfunction()

set(COMMON_SOURCES
    common/payload_codec.cpp
)

duckdetector_native_unit(duckdetector_common
    ${COMMON_SOURCES}
)

duckdetector_native_unit(duckdetector_tee
    tee/common/jni_bridge.cpp
    tee/common/result_codec.cpp
    tee/common/syscall_facade.cpp
    tee/common/timing_stats.cpp
    tee/keystore/environment_probe.cpp
    tee/trickystore/trickystore_honeypot.cpp
    tee/trickystore/trickystore_hooks.cpp
    tee/trickystore/trickystore_probe.cpp
    tee/der/der_probe.cpp
)
if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_sources(duckdetector_tee PRIVATE
        tee/asm/arm64/syscall_fastpath.S
        tee/asm/arm64/tee_timer_arm64.S
    )
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    target_sources(duckdetector_tee PRIVATE
        tee/asm/arm/syscall_fastpath.S
    )
elseif(ANDROID_ABI STREQUAL "x86")
    target_sources(duckdetector_tee PRIVATE
        tee/asm/x86/syscall_fastpath.S
    )
elseif(ANDROID_ABI STREQUAL "x86_64")
    target_sources(duckdetector_tee PRIVATE
        tee/asm/x86_64/syscall_fastpath.S
    )
endif()

duckdetector_native_unit(duckdetector_packageinventory
    packageinventory/native_bridge.cpp
)

duckdetector_native_unit(duckdetector_su
    su/native_bridge.cpp
)

duckdetector_native_unit(duckdetector_selinuxpolicy
    selinuxpolicy/context_validity_checks.cpp
    selinuxpolicy/context_validity_probe.cpp
    selinuxpolicy/context_validity_symbols.cpp
    selinuxpolicy/context_validity_native_bridge.cpp
    selinuxpolicy/dirty_policy_probe.cpp
)

duckdetector_native_unit(duckdetector_selinux
    selinux/audit_probe.cpp
    selinux/native_bridge.cpp
)

duckdetector_native_unit(duckdetector_customrom
    customrom/native_bridge.cpp
    customrom/property_area_scan.cpp
    customrom/property_integrity_probe.cpp
    customrom/symbol_probe.cpp
)

duckdetector_native_unit(duckdetector_kernelcheck
    kernelcheck/arm64_cpu_identity_probe.cpp
    kernelcheck/native_bridge.cpp
)

duckdetector_native_unit(duckdetector_systemproperties
    systemproperties/property_utils.cpp
    systemproperties/boot_param_utils.cpp
    systemproperties/prop_area_probe.cpp
    systemproperties/readonly_handle_probe.cpp
    systemproperties/native_bridge.cpp
)

duckdetector_native_unit(duckdetector_bootloader
    bootloader/widevine_native_bridge.cpp
)

duckdetector_native_unit(duckdetector_mount
    mount/detect_filesystems.cpp
    mount/detect_mount_tables.cpp
    mount/detect_paths.cpp
    mount/detector_core.cpp
    mount/detector_support.cpp
    mount/native_bridge.cpp
)

duckdetector_native_unit(duckdetector_preload
    preload/early_detector.cpp
    preload/virtualization_early_detector.cpp
    preload/preload_entry.cpp
    preload/preload_jni.cpp
)

duckdetector_native_unit(duckdetector_memory
    memory/common/codec.cpp
    memory/common/maps_reader.cpp
    memory/detectors/function_hook_detector.cpp
    memory/detectors/maps_anomaly_detector.cpp
    memory/detectors/fd_detector.cpp
    memory/detectors/signal_detector.cpp
    memory/detectors/vdso_detector.cpp
    memory/detectors/linker_detector.cpp
    memory/snapshot_builder.cpp
    memory/native_bridge.cpp
)

duckdetector_native_unit(duckdetector_playintegrityfix
    playintegrityfix/common/codec.cpp
    playintegrityfix/probes/property_probe.cpp
    playintegrityfix/probes/maps_probe.cpp
    playintegrityfix/snapshot_builder.cpp
    playintegrityfix/native_bridge.cpp
)

duckdetector_native_unit(duckdetector_nativeroot
    nativeroot/common/codec.cpp
    nativeroot/common/io_utils.cpp
    nativeroot/cgroup_bridge.cpp
    nativeroot/throne_hunt_native_bridge.cpp
    nativeroot/probes/prctl_probe.cpp
    nativeroot/probes/kernelpatch_nr_supercall_latency_probe.cpp
    nativeroot/probes/kernelpatch_superkey_probe.cpp
    nativeroot/probes/devpts_abnormal_permission_probe.cpp
    nativeroot/probes/permission_boundary_probe.cpp
    nativeroot/probes/ksu_supercall_probe.cpp
    nativeroot/probes/susfs_probe.cpp
    nativeroot/probes/self_process_ioc_probe.cpp
    nativeroot/probes/throne_hunt_watch_probe.cpp
    nativeroot/probes/cgroup_process_probe.cpp
    nativeroot/probes/path_probe.cpp
    nativeroot/probes/process_probe.cpp
    nativeroot/probes/kernel_probe.cpp
    nativeroot/probes/property_probe.cpp
    nativeroot/snapshot_builder.cpp
    nativeroot/native_bridge.cpp
)

duckdetector_native_unit(duckdetector_lsposed
    lsposed/common/codec.cpp
    lsposed/probes/maps_probe.cpp
    lsposed/probes/heap_probe.cpp
    lsposed/snapshot_builder.cpp
    lsposed/native_bridge.cpp
)

duckdetector_native_unit(duckdetector_zygisk
    zygisk/common/codec.cpp
    zygisk/probes/fd_trap.cpp
    zygisk/probes/environment_probe.cpp
    zygisk/probes/solist_probe.cpp
    zygisk/probes/vmap_probe.cpp
    zygisk/probes/atexit_probe.cpp
    zygisk/probes/smaps_probe.cpp
    zygisk/probes/namespace_probe.cpp
    zygisk/probes/linker_hook_probe.cpp
    zygisk/probes/stack_leak_probe.cpp
    zygisk/probes/seccomp_probe.cpp
    zygisk/probes/heap_entropy_probe.cpp
    zygisk/probes/thread_probe.cpp
    zygisk/probes/fd_probe.cpp
    zygisk/snapshot_builder.cpp
    zygisk/native_bridge.cpp
    zygisk/fdtrap_bridge.cpp
)

duckdetector_native_unit(duckdetector_virtualization
    virtualization/egl_probe.cpp
    virtualization/snapshot_builder.cpp
    virtualization/honeypot_traps.cpp
    virtualization/native_bridge.cpp
    virtualization/sacrificial_syscall_pack.cpp
)
if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_sources(duckdetector_virtualization PRIVATE
        virtualization/asm/arm64/virtualization_traps.S
    )
endif()

add_library(duckdetector SHARED)
set_property(TARGET duckdetector PROPERTY LINKER_LANGUAGE CXX)
if(ipo_supported)
    set_property(TARGET duckdetector PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
endif()

target_link_options(duckdetector PRIVATE
    $<$<CONFIG:Release>:-Wl,--gc-sections>
)

target_link_libraries(duckdetector PRIVATE
    duckdetector_common
    duckdetector_tee
    duckdetector_packageinventory
    duckdetector_su
    duckdetector_selinuxpolicy
    duckdetector_selinux
    duckdetector_customrom
    duckdetector_kernelcheck
    duckdetector_systemproperties
    duckdetector_bootloader
    duckdetector_mount
    duckdetector_preload
    duckdetector_memory
    duckdetector_playintegrityfix
    duckdetector_nativeroot
    duckdetector_lsposed
    duckdetector_zygisk
    duckdetector_virtualization
    android
    EGL
    GLESv2
    log
    mediandk
)

# Android 17 native isolated services are loaded by zygote_next without ART. The framework's
# default contract loads libmain.so and calls ANativeService_onCreate. It compiles its own copy of
# the common sources because it keeps hidden visibility in every build type.
add_library(main SHARED
    ${COMMON_SOURCES}
    mount/zygotenext/native_service.cpp
)

target_compile_options(main PRIVATE
    -Wall
    -Wextra
    -fvisibility=hidden
    -fvisibility-inlines-hidden
)

target_include_directories(main PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(main
    dl
)
