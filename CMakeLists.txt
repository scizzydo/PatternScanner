# Header-only: for add_subdirectory / FetchContent users. Links as PatternScanner::PatternScanner.
# Tests are a separate project in tests/.
cmake_minimum_required(VERSION 3.16)
project(PatternScanner CXX)

add_library(PatternScanner INTERFACE)
add_library(PatternScanner::PatternScanner ALIAS PatternScanner)
target_include_directories(PatternScanner INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(PatternScanner INTERFACE cxx_std_17)
