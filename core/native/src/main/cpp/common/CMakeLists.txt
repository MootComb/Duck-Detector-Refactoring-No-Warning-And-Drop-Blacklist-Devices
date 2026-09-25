# Payload helpers every unit shares. libmain.so compiles its own copy of these sources.
set(DUCKDETECTOR_COMMON_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/payload_codec.cpp PARENT_SCOPE)

duckdetector_native_unit(duckdetector_common
    payload_codec.cpp
)
