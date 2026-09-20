cmake_minimum_required(VERSION 3.20)

project(binx VERSION 1.0.0 LANGUAGES CXX)

include(CTest)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BINX_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

set(BINX_CORE_SOURCES
    src/core/binary.cpp
    src/core/byte_reader.cpp
    src/core/text.cpp
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
    src/analysis/report.cpp
)

add_library(binx_core STATIC ${BINX_CORE_SOURCES})
target_include_directories(binx_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(binx_core PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(binx_core PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(binx_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

if(WIN32)
    target_link_libraries(binx_core PUBLIC bcrypt)
else()
    find_package(OpenSSL REQUIRED COMPONENTS Crypto)
    target_link_libraries(binx_core PUBLIC OpenSSL::Crypto)
endif()

add_executable(binx
    src/main.cpp
    src/cli/commands.cpp
    src/cli/io.cpp
    src/cli/options.cpp
    src/cli/runner.cpp
    src/cli/analysis_output.cpp
    src/cli/dependency_output.cpp
    src/cli/output.cpp
)
target_link_libraries(binx PRIVATE binx_core)

if(MSVC)
    target_compile_options(binx PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(binx PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

if(BINX_ENABLE_SANITIZERS AND NOT MSVC)
    target_compile_options(binx_core PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(binx_core PRIVATE -fsanitize=address,undefined)
    target_compile_options(binx PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(binx PRIVATE -fsanitize=address,undefined)
elseif(BINX_ENABLE_SANITIZERS AND MSVC)
    target_compile_options(binx PRIVATE /fsanitize=address)
    target_compile_options(binx_core PRIVATE /fsanitize=address)
endif()

if(BUILD_TESTING)
    add_executable(binx_core_tests tests/test_core.cpp)
    add_executable(binx_cli_tests tests/test_cli.cpp)
    target_link_libraries(binx_core_tests PRIVATE binx_core)
    target_link_libraries(binx_cli_tests PRIVATE binx_core)

    foreach(test_target IN ITEMS binx_core_tests binx_cli_tests)
        if(MSVC)
            target_compile_options(${test_target} PRIVATE /W4 /permissive- /utf-8)
        else()
            target_compile_options(${test_target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
        endif()

        if(BINX_ENABLE_SANITIZERS AND NOT MSVC)
            target_compile_options(${test_target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
            target_link_options(${test_target} PRIVATE -fsanitize=address,undefined)
        elseif(BINX_ENABLE_SANITIZERS AND MSVC)
            target_compile_options(${test_target} PRIVATE /fsanitize=address)
        endif()
    endforeach()

    add_test(NAME binx_core COMMAND binx_core_tests)
    add_test(NAME binx_cli COMMAND binx_cli_tests)
    add_test(NAME binx_help COMMAND binx --help)
    add_test(NAME binx_version COMMAND binx --version)
endif()

install(TARGETS binx binx_core
    EXPORT BinXTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT BinXTargets
    FILE BinXTargets.cmake
    NAMESPACE BinX::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/BinX
)

configure_package_config_file(
    cmake/BinXConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/BinXConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/BinX
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/BinXConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/BinXConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/BinXConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/BinX
)

set(CPACK_PACKAGE_NAME "binx")
set(CPACK_PACKAGE_VENDOR "BinX")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Offline developer-first binary analysis toolkit")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT "BinX maintainers")
set(CPACK_GENERATOR "ZIP;TGZ")
include(CPack)
