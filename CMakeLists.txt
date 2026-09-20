cmake_minimum_required(VERSION 3.20)
project(binx VERSION 0.95.0 LANGUAGES CXX)
include(CTest)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(binx
    src/main.cpp
    src/core/binary.cpp
    src/core/byte_reader.cpp
    src/formats/detect.cpp
    src/formats/pe.cpp
    src/formats/elf.cpp
    src/formats/macho.cpp
    src/hashing/hasher.cpp
    src/cli/output.cpp
    src/analysis/byte_analysis.cpp
    src/cli/analysis_output.cpp
    src/analysis/dependencies.cpp
    src/analysis/disassembly.cpp
    src/analysis/symbols.cpp
    src/analysis/diff.cpp
    src/analysis/crash.cpp
    src/analysis/report.cpp
    src/cli/dependency_output.cpp
)
target_include_directories(binx PRIVATE include)
if(MSVC)
    target_compile_options(binx PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(binx PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()
if(WIN32)
    target_link_libraries(binx PRIVATE bcrypt)
else()
    find_package(OpenSSL REQUIRED COMPONENTS Crypto)
    target_link_libraries(binx PRIVATE OpenSSL::Crypto)
endif()

if(BUILD_TESTING)
    add_executable(binx_tests
        tests/test_core.cpp
        src/core/binary.cpp
        src/core/byte_reader.cpp
        src/formats/detect.cpp
        src/formats/pe.cpp
        src/formats/elf.cpp
        src/formats/macho.cpp
        src/hashing/hasher.cpp
        src/analysis/byte_analysis.cpp
        src/analysis/dependencies.cpp
        src/analysis/disassembly.cpp
        src/analysis/symbols.cpp
        src/analysis/diff.cpp
        src/analysis/crash.cpp
    )
    target_include_directories(binx_tests PRIVATE include)
    if(MSVC)
        target_compile_options(binx_tests PRIVATE /W4 /permissive- /utf-8)
    else()
        target_compile_options(binx_tests PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
    if(WIN32)
        target_link_libraries(binx_tests PRIVATE bcrypt)
    else()
        target_link_libraries(binx_tests PRIVATE OpenSSL::Crypto)
    endif()
    add_test(NAME binx_unit COMMAND binx_tests)
    add_test(NAME binx_help COMMAND binx --help)
    add_test(NAME binx_version COMMAND binx --version)
endif()

include(GNUInstallDirs)
install(TARGETS binx RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} BUNDLE DESTINATION .)
