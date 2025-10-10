cmake_minimum_required(VERSION 3.15)
project(aegis LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(AEGIS_BUILD_TESTS "Build test executables" ON)

# for better organization in IDEs
set_property(GLOBAL PROPERTY USE_FOLDERS ON)


find_package(PkgConfig REQUIRED)

# --- libsodium ---
if (NOT SODIUM_FOUND)
    message(WARNING "pkg-config could not find libsodium, trying manual lookup...")

    find_path(SODIUM_INCLUDE_DIR sodium.h)
    find_library(SODIUM_LIBRARY sodium)


    if (NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
        message(FATAL_ERROR "Could not find libsodium! Install it via 'brew install libsodium' or 'apt install libsodium-dev'")
    endif()

    set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
    set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
else()
    message(STATUS "Found libsodium via pkg-config: ${SODIUM_VERSION}")
endif()

# --- ZLIB ---
find_package(ZLIB REQUIRED)
message(STATUS "Found ZLIB: ${ZLIB_VERSION}")

# aegis_core library
add_library(aegis_core
    src/crypto/aegis_crypto.cpp
    src/core/file_io.cpp
    src/core/utils.cpp
)

target_include_directories(aegis_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${SODIUM_INCLUDE_DIRS}
        ${ZLIB_INCLUDE_DIRS}
)

target_link_libraries(aegis_core
    PUBLIC
        ${SODIUM_LIBRARIES}
        ZLIB::ZLIB
)

target_compile_options(aegis_core
    PRIVATE
        ${SODIUM_CFLAGS_OTHER}
)

# aegis CLI executable
add_executable(aegis src/cli/main.cpp)

target_link_libraries(aegis
    PRIVATE
        aegis_core
)

target_include_directories(aegis PRIVATE
    ${SODIUM_INCLUDE_DIRS}
)

# tests
if (AEGIS_BUILD_TESTS)
    enable_testing()
    add_executable(aegis_tests tests/test_roundtrip.cpp)

    target_link_libraries(aegis_tests PRIVATE aegis_core)

    add_test(NAME roundtrip COMMAND aegis_tests)
endif()

# summary
message(STATUS "")
message(STATUS "===================================")
message(STATUS "  AEGIS Build Configuration Summary")
message(STATUS "-----------------------------------")
message(STATUS "  C++ Standard:      ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Tests:       ${AEGIS_BUILD_TESTS}")
message(STATUS "  Sodium Include:    ${SODIUM_INCLUDE_DIRS}")
message(STATUS "  Sodium Library:    ${SODIUM_LIBRARIES}")
message(STATUS "  Zlib Include:      ${ZLIB_INCLUDE_DIRS}")
message(STATUS "  Zlib Library:      ${ZLIB_LIBRARIES}")
message(STATUS "===================================")
message(STATUS "")
