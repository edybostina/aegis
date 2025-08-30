cmake_minimum_required(VERSION 3.12)
project(aegis LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_path(SODIUM_INCLUDE_DIR sodium.h)

find_library(SODIUM_LIBRARY sodium)

if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found! Please install it with `brew install libsodium or any package manager`")
endif()


add_library(aegis_core
    src/crypto/aegis_crypto.cpp
    src/core/file_io.cpp
    src/core/utils.cpp
)

target_include_directories(aegis_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIR}
)

target_link_libraries(aegis_core PUBLIC ${SODIUM_LIBRARY})


add_executable(aegis src/cli/main.cpp)
target_link_libraries(aegis PRIVATE aegis_core ${SODIUM_LIBRARY})
target_include_directories(aegis PRIVATE ${SODIUM_INCLUDE_DIR})


if (AEGIS_BUILD_TESTS)
    enable_testing()
    add_executable(aegis_tests tests/test_roundtrip.cpp)
    target_link_libraries(aegis_tests PRIVATE aegis_core ${SODIUM_LIBRARY})
    add_test(NAME roundtrip COMMAND aegis_tests)
endif()