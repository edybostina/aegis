cmake_minimum_required(VERSION 3.15)
project(aegis LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(AEGIS_BUILD_TESTS "Build test executables" ON)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# --- libsodium ---
find_package(unofficial-sodium CONFIG QUIET)
if (unofficial-sodium_FOUND)
    message(STATUS "Found libsodium via vcpkg")
    set(SODIUM_LIBRARIES unofficial-sodium::sodium)
    get_target_property(SODIUM_INCLUDE_DIRS unofficial-sodium::sodium INTERFACE_INCLUDE_DIRECTORIES)
else()
    find_package(PkgConfig QUIET)
    if (PkgConfig_FOUND)
        pkg_check_modules(SODIUM QUIET libsodium)
    endif()

    if (SODIUM_FOUND)
        if (SODIUM_LIBRARIES STREQUAL "sodium" OR SODIUM_LIBRARIES STREQUAL "-lsodium")
            message(WARNING "pkg-config found libsodium but didn't provide a valid path; trying manual lookup...")

            find_library(SODIUM_LIBRARY
                NAMES sodium libsodium
                PATH_SUFFIXES lib
                PATHS
                    /usr/local /usr /opt/local
                    /opt/homebrew /opt/homebrew/opt/libsodium
            )

            if (SODIUM_LIBRARY)
                set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
                message(STATUS "Resolved libsodium manually: ${SODIUM_LIBRARY}")
            else()
                message(FATAL_ERROR "Could not find actual libsodium library even though pkg-config reported it.")
            endif()
        else()
            message(STATUS "Found libsodium via pkg-config: ${SODIUM_VERSION}")
        endif()
    else()
        message(WARNING "pkg-config could not find libsodium, trying manual lookup...")

        find_path(SODIUM_INCLUDE_DIR
            NAMES sodium.h
            PATH_SUFFIXES include include/sodium
            PATHS /usr/local /usr /opt/local /opt/homebrew /opt/homebrew/opt/libsodium
        )

        find_library(SODIUM_LIBRARY
            NAMES sodium libsodium
            PATH_SUFFIXES lib
            PATHS /usr/local /usr /opt/local /opt/homebrew /opt/homebrew/opt/libsodium
        )

        if (NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
            message(FATAL_ERROR "Could not find libsodium!
Please install it via:
  macOS:  brew install libsodium
  Linux:  sudo apt install libsodium-dev
  Windows: vcpkg install libsodium
")
        endif()

        set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
        set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
    endif()
endif()

# zlib
find_package(ZLIB REQUIRED)
message(STATUS "Found ZLIB: ${ZLIB_VERSION}")

# aegis_core
add_library(aegis_core
    src/crypto/aegis_crypto.cpp
    src/core/file_io.cpp
    src/core/utils.cpp
)

target_include_directories(aegis_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if (TARGET unofficial-sodium::sodium)
    target_link_libraries(aegis_core
        PUBLIC
            unofficial-sodium::sodium
            ZLIB::ZLIB
    )
else()
    target_include_directories(aegis_core PUBLIC ${SODIUM_INCLUDE_DIRS} ${ZLIB_INCLUDE_DIRS})
    target_link_libraries(aegis_core
        PUBLIC
            ${SODIUM_LIBRARIES}
            ZLIB::ZLIB
    )
    target_compile_options(aegis_core PRIVATE ${SODIUM_CFLAGS_OTHER})
endif()

# cli
add_executable(aegis src/cli/main.cpp)
target_link_libraries(aegis PRIVATE aegis_core)
target_include_directories(aegis PRIVATE ${SODIUM_INCLUDE_DIRS})

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
