duckdetector_native_unit(duckdetector_mount
    detect_filesystems.cpp
    detect_mount_tables.cpp
    detect_paths.cpp
    detector_core.cpp
    detector_support.cpp
    native_bridge.cpp
)

# zygote_next loads libmain.so without ART; zygotenext/CMakeLists.txt builds it.
add_subdirectory(zygotenext)
