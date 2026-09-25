# Android 17 native isolated services are loaded by zygote_next without ART. The framework's
# default contract loads libmain.so and calls ANativeService_onCreate. It compiles its own copy of
# the common sources because it keeps hidden visibility in every build type.
add_library(main SHARED
    ${DUCKDETECTOR_COMMON_SOURCES}
    native_service.cpp
)

target_compile_options(main PRIVATE
    -Wall
    -Wextra
    -fvisibility=hidden
    -fvisibility-inlines-hidden
)

target_include_directories(main PRIVATE
    ${DUCKDETECTOR_NATIVE_INCLUDE_DIRS}
)

target_link_libraries(main
    dl
)
