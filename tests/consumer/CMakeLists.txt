cmake_minimum_required(VERSION 3.24)

project(ed2k_consumer LANGUAGES CXX)

find_package(ed2k 2.2 CONFIG REQUIRED)

add_executable(ed2k_consumer main.cpp)
target_compile_features(ed2k_consumer PRIVATE cxx_std_20)
target_link_libraries(ed2k_consumer PRIVATE ed2k::core)

enable_testing()
add_test(NAME ed2k_consumer_smoke COMMAND ed2k_consumer)
