cmake_minimum_required(VERSION 3.24)
project(ed2kengine LANGUAGES CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(ED2K_BUILD_TESTS "Build tests" ON)

find_package(spdlog CONFIG REQUIRED)
find_package(tl-expected CONFIG REQUIRED)
find_package(ZLIB REQUIRED)

add_library(ed2k_core)
target_include_directories(ed2k_core
  PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(ed2k_core PUBLIC spdlog::spdlog tl::expected)
# 后续任务用 target_sources(ed2k_core PRIVATE ...) 追加源文件
target_sources(ed2k_core PRIVATE src/util/version.cpp)
target_sources(ed2k_core PRIVATE src/util/error.cpp)
target_sources(ed2k_core PRIVATE src/crypto/md4.cpp)
target_sources(ed2k_core PRIVATE src/crypto/sha1.cpp)
target_sources(ed2k_core PRIVATE src/core/hash.cpp)
target_sources(ed2k_core PRIVATE src/codec/byte_io.cpp)
target_sources(ed2k_core PRIVATE src/codec/tag.cpp)
target_sources(ed2k_core PRIVATE src/hash/ed2k_hasher.cpp)

add_executable(ed2k-tool apps/cli/main.cpp)
target_link_libraries(ed2k-tool PRIVATE ed2k_core)

if(ED2K_BUILD_TESTS)
  enable_testing()
  find_package(GTest CONFIG REQUIRED)
  add_executable(ed2k_tests tests/smoke_test.cpp tests/error_test.cpp tests/md4_test.cpp tests/sha1_test.cpp tests/core_hash_test.cpp tests/byte_io_test.cpp tests/tag_test.cpp tests/ed2k_hasher_test.cpp)
  target_link_libraries(ed2k_tests PRIVATE ed2k_core GTest::gtest GTest::gtest_main)
  target_include_directories(ed2k_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  include(GoogleTest)
  gtest_discover_tests(ed2k_tests)
endif()
