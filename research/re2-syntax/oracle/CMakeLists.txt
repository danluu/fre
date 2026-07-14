cmake_minimum_required(VERSION 3.22)
project(fre_re2_syntax_oracle LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17 CACHE STRING "C++ standard shared by Abseil and RE2" FORCE)
set(CMAKE_CXX_STANDARD_REQUIRED ON CACHE BOOL "Require the selected C++ standard" FORCE)
set(CMAKE_CXX_EXTENSIONS OFF CACHE BOOL "Use portable C++ mode" FORCE)

if(NOT DEFINED RE2_SOURCE)
  message(FATAL_ERROR "set RE2_SOURCE to the pinned RE2 checkout")
endif()

if(DEFINED ABSL_SOURCE)
  add_subdirectory("${ABSL_SOURCE}" absl EXCLUDE_FROM_ALL)
endif()

set(RE2_INSTALL OFF CACHE BOOL "" FORCE)
set(RE2_TEST OFF CACHE BOOL "" FORCE)
set(RE2_BENCHMARK OFF CACHE BOOL "" FORCE)
set(RE2_BUILD_TESTING OFF CACHE BOOL "" FORCE)
add_subdirectory("${RE2_SOURCE}" re2 EXCLUDE_FROM_ALL)

add_executable(fre-re2-oracle oracle.cc)
target_compile_features(fre-re2-oracle PRIVATE cxx_std_17)
target_link_libraries(fre-re2-oracle PRIVATE re2::re2)
