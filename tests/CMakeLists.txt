# Tests and benchmarks. Not part of the library; the headers stay include-only.
#   cmake -S tests -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build --config Release
#   ctest --test-dir build -C Release --output-on-failure
cmake_minimum_required(VERSION 3.16)
project(PatternScannerTests CXX)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Threads REQUIRED)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)
add_compile_definitions(_CRT_SECURE_NO_WARNINGS)   # fopen in the test code
enable_testing()

add_executable(test_patterns test_patterns.cpp)
add_executable(test_patterns_nosimd test_patterns.cpp)
target_compile_definitions(test_patterns_nosimd PRIVATE PATTERNS_NO_SIMD)
add_executable(test_cpp17 test_cpp17.cpp)
set_target_properties(test_cpp17 PROPERTIES CXX_STANDARD 17)
add_executable(example_pointer_table example_pointer_table.cpp)
add_executable(bench_scan bench_scan.cpp)
add_executable(bench_multi bench_multi.cpp)

foreach(t test_patterns test_patterns_nosimd example_pointer_table bench_multi)
    target_link_libraries(${t} PRIVATE Threads::Threads)
endforeach()

add_test(NAME test_patterns COMMAND test_patterns)
add_test(NAME test_patterns_nosimd COMMAND test_patterns_nosimd)
add_test(NAME test_cpp17 COMMAND test_cpp17)
add_test(NAME example_pointer_table COMMAND example_pointer_table)
