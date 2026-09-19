cmake_minimum_required(VERSION 3.20)
project(binx VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(binx
    src/main.cpp
    src/core/binary.cpp
    src/core/byte_reader.cpp
    src/formats/detect.cpp
    src/formats/pe.cpp
    src/formats/elf.cpp
    src/hashing/hasher.cpp
    src/cli/output.cpp
)

target_include_directories(binx PRIVATE include)

if(MSVC)
    target_compile_options(binx PRIVATE /W4 /permissive-)
else()
    target_compile_options(binx PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
    target_link_libraries(binx PRIVATE bcrypt)
endif()

enable_testing()
add_executable(binx_tests
    tests/test_core.cpp
    src/core/binary.cpp
    src/core/byte_reader.cpp
    src/formats/detect.cpp
    src/formats/pe.cpp
    src/formats/elf.cpp
    src/hashing/hasher.cpp
)
target_include_directories(binx_tests PRIVATE include)
if(WIN32)
    target_link_libraries(binx_tests PRIVATE bcrypt)
endif()
add_test(NAME binx_tests COMMAND binx_tests)
