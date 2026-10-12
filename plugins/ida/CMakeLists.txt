# PatternScanner IDA plugin (IDA 9.x). Needs the IDA SDK with ida-cmake, which isn't part of this repo:
#   cmake -S plugins/ida -B build-ida -DIDASDK=/path/to/ida-sdk [-DIDABIN=/path/to/ida]
#   cmake --build build-ida --config Release
# The plugin is copied to $IDABIN/plugins (IDABIN defaults to the SDK's bin folder).
#
# Optional idalib test of the search, against small ELF files assembled with clang and lld:
#   -DIDA_INSTALL_DIR=/path/to/ida   then   ctest --test-dir build-ida -C Release --output-on-failure
cmake_minimum_required(VERSION 3.27)
project(PatternScannerIDA CXX)
set(CMAKE_CXX_STANDARD 17)

set(IDASDK "$ENV{IDASDK}" CACHE PATH "IDA SDK: a GitHub checkout (ida-cmake in src/cmake) or a zip SDK with ida-cmake cloned into it")
if(NOT IDASDK)
    message(FATAL_ERROR "Set IDASDK (-DIDASDK=... or the environment variable) to your IDA SDK")
endif()
# ida-cmake reads the environment variable
set(ENV{IDASDK} "${IDASDK}")
find_file(IDA_CMAKE_BOOTSTRAP bootstrap.cmake
    PATHS "${IDASDK}/src/cmake" "${IDASDK}/cmake" "${IDASDK}/ida-cmake" NO_DEFAULT_PATH NO_CACHE)
if(NOT IDA_CMAKE_BOOTSTRAP)
    message(FATAL_ERROR "ida-cmake not found in ${IDASDK}. GitHub SDK: git submodule update --init src/cmake. "
                        "Zip SDK: git clone https://github.com/allthingsida/ida-cmake ${IDASDK}/ida-cmake")
endif()
include(${IDA_CMAKE_BOOTSTRAP})
# The bootstrap points the environment variable at src/ for GitHub checkouts; idasdk reads this variable first
set(IDASDK "$ENV{IDASDK}")
find_package(idasdk REQUIRED)

add_subdirectory(../.. PatternScanner)

ida_add_plugin(pattern_scanner
    SOURCES pattern_scanner.cpp
    LIBRARIES PatternScanner::PatternScanner
)

set(IDA_INSTALL_DIR "" CACHE PATH "IDA install with idalib and a license; builds the search test")
if(IDA_INSTALL_DIR)
    find_program(CLANG NAMES clang)
    find_program(LLD NAMES ld.lld ld.lld-21 ld.lld-20 ld.lld-19 ld.lld-18)
    if(NOT CLANG OR NOT LLD)
        message(FATAL_ERROR "The search test assembles its fixtures with clang and ld.lld")
    endif()
    set(fixtures)
    foreach(f x64:x86_64:x86.S x86:i386:x86.S arm64:aarch64:arm64.S)
        string(REPLACE ":" ";" f "${f}")
        list(GET f 0 name)
        list(GET f 1 triple)
        list(GET f 2 src)
        set(out ${CMAKE_CURRENT_BINARY_DIR}/fixture_${name}.elf)
        add_custom_command(OUTPUT ${out}
            COMMAND ${CLANG} --target=${triple}-linux-gnu -nostdlib -static --ld-path=${LLD}
                    -o ${out} ${CMAKE_CURRENT_SOURCE_DIR}/test/${src}
            DEPENDS test/${src})
        list(APPEND fixtures ${out})
    endforeach()
    add_custom_target(search_fixtures ALL DEPENDS ${fixtures})

    ida_add_idalib(test_search TYPE EXECUTABLE SOURCES test/test_search.cpp LIBRARIES PatternScanner::PatternScanner)
    if(APPLE OR UNIX)
        set_target_properties(test_search PROPERTIES BUILD_RPATH "${IDA_INSTALL_DIR}")
    endif()
    enable_testing()
    add_test(NAME test_search COMMAND test_search ${fixtures})
    if(WIN32)
        set_tests_properties(test_search PROPERTIES ENVIRONMENT "PATH=${IDA_INSTALL_DIR};$ENV{PATH}")
    endif()
endif()
