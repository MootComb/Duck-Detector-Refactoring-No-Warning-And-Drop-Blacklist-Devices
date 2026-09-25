duckdetector_native_unit(duckdetector_virtualization
    egl_probe.cpp
    snapshot_builder.cpp
    honeypot_traps.cpp
    native_bridge.cpp
    sacrificial_syscall_pack.cpp
)

if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_sources(duckdetector_virtualization PRIVATE
        asm/arm64/virtualization_traps.S
    )
endif()
