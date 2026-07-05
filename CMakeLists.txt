cmake_minimum_required(VERSION 3.24)
project(ed2kengine LANGUAGES CXX VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(ED2K_BUILD_TESTS "Build tests" ON)

find_package(spdlog CONFIG REQUIRED)
find_package(tl-expected CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(boost_asio CONFIG REQUIRED)
find_package(Threads REQUIRED)
include(GNUInstallDirs)

add_library(ed2k_core)
target_include_directories(ed2k_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(ed2k_core PUBLIC spdlog::spdlog tl::expected Boost::asio Threads::Threads)
target_link_libraries(ed2k_core PRIVATE ZLIB::ZLIB)
# Boost.Asio 在 Windows 上需明确目标版本（否则默认假设 Win7 并告警）；本项目目标 Win10/11。
target_compile_definitions(ed2k_core PUBLIC $<$<PLATFORM_ID:Windows>:_WIN32_WINNT=0x0A00>)
# 后续任务用 target_sources(ed2k_core PRIVATE ...) 追加源文件
target_sources(ed2k_core PRIVATE src/util/version.cpp)
target_sources(ed2k_core PRIVATE src/util/error.cpp)
target_sources(ed2k_core PRIVATE src/crypto/md4.cpp)
target_sources(ed2k_core PRIVATE src/crypto/md5.cpp)
target_sources(ed2k_core PRIVATE src/crypto/rc4.cpp)
target_sources(ed2k_core PRIVATE src/crypto/sha1.cpp)
target_sources(ed2k_core PRIVATE src/core/hash.cpp)
target_sources(ed2k_core PRIVATE src/infra/category.cpp)
target_sources(ed2k_core PRIVATE src/infra/client_list.cpp)
target_sources(ed2k_core PRIVATE src/infra/friend_list.cpp)
target_sources(ed2k_core PRIVATE src/infra/ip_filter.cpp)
target_sources(ed2k_core PRIVATE src/infra/preferences.cpp)
target_sources(ed2k_core PRIVATE src/infra/statistics.cpp)
target_sources(ed2k_core PRIVATE src/codec/byte_io.cpp)
target_sources(ed2k_core PRIVATE src/codec/tag.cpp)
target_sources(ed2k_core PRIVATE src/hash/ed2k_hasher.cpp)
target_sources(ed2k_core PRIVATE src/hash/aich_hasher.cpp)
target_sources(ed2k_core PRIVATE src/link/ed2k_link.cpp)
target_sources(ed2k_core PRIVATE src/metfile/server_met.cpp)
target_sources(ed2k_core PRIVATE src/metfile/known_part_met.cpp)
target_sources(ed2k_core PRIVATE src/share/client_credits.cpp)
target_sources(ed2k_core PRIVATE src/share/known_file.cpp)
target_sources(ed2k_core PRIVATE src/share/upload_queue.cpp)
target_sources(ed2k_core PRIVATE src/share/upload_session.cpp)
target_sources(ed2k_core PRIVATE src/share/upload_throttler.cpp)
target_sources(ed2k_core PRIVATE src/util/log.cpp)
target_sources(ed2k_core PRIVATE src/net/framing.cpp)
target_sources(ed2k_core PRIVATE src/net/inflate.cpp)
target_sources(ed2k_core PRIVATE src/net/runtime.cpp)
target_sources(ed2k_core PRIVATE src/net/connection.cpp)
target_sources(ed2k_core PRIVATE src/net/udp_framing.cpp)
target_sources(ed2k_core PRIVATE src/net/udp_socket.cpp)
target_sources(ed2k_core PRIVATE src/net/udp_obfuscation.cpp)
target_sources(ed2k_core PRIVATE src/net/encrypted_stream_socket.cpp)
target_sources(ed2k_core PRIVATE src/server/search_query.cpp)
target_sources(ed2k_core PRIVATE src/server/messages.cpp)
target_sources(ed2k_core PRIVATE src/server/udp_messages.cpp)
target_sources(ed2k_core PRIVATE src/server/connection.cpp)
target_sources(ed2k_core PRIVATE src/server/udp_connection.cpp)
target_sources(ed2k_core PRIVATE src/peer/c2c_messages.cpp)
target_sources(ed2k_core PRIVATE src/peer/c2c_connection.cpp)
target_sources(ed2k_core PRIVATE src/peer/inbound_listener.cpp)
target_sources(ed2k_core PRIVATE src/download/part_file.cpp)
target_sources(ed2k_core PRIVATE src/download/block_allocator.cpp)
target_sources(ed2k_core PRIVATE src/download/aich_checker.cpp)
target_sources(ed2k_core PRIVATE src/download/download.cpp)
target_sources(ed2k_core PRIVATE src/app/server_session.cpp)
target_sources(ed2k_core PRIVATE src/kad/kad_id.cpp)
target_sources(ed2k_core PRIVATE src/kad/routing_table.cpp)
target_sources(ed2k_core PRIVATE src/kad/nodes_dat.cpp)
target_sources(ed2k_core PRIVATE src/kad/keywords.cpp)
target_sources(ed2k_core PRIVATE src/kad/messages.cpp)
target_sources(ed2k_core PRIVATE src/kad/udp_crypto.cpp)
target_sources(ed2k_core PRIVATE src/kad/indexed.cpp)
target_sources(ed2k_core PRIVATE src/kad/network.cpp)

add_executable(ed2k-tool apps/cli/main.cpp)
target_link_libraries(ed2k-tool PRIVATE ed2k_core)

# --- 安装/打包 (R0-5) ---
# 交付形态: 可嵌入静态库 ed2k_core + CLI ed2k-tool + 公共头 include/ed2k/
install(TARGETS ed2k_core ed2k-tool
  EXPORT ed2kTargets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ed2k
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.hpp")
install(EXPORT ed2kTargets
  FILE ed2kTargets.cmake
  NAMESPACE ed2k::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ed2k)

if(ED2K_BUILD_TESTS)
  enable_testing()
  find_package(GTest CONFIG REQUIRED)
  add_executable(ed2k_tests tests/smoke_test.cpp tests/error_test.cpp tests/md4_test.cpp tests/md5_test.cpp tests/rc4_test.cpp tests/sha1_test.cpp tests/core_hash_test.cpp tests/ip_filter_test.cpp tests/preferences_test.cpp tests/statistics_test.cpp tests/category_test.cpp tests/friend_client_list_test.cpp tests/byte_io_test.cpp tests/tag_test.cpp tests/ed2k_hasher_test.cpp tests/aich_hasher_test.cpp tests/ed2k_link_test.cpp tests/server_met_test.cpp tests/known_part_met_test.cpp tests/share_known_file_test.cpp tests/upload_queue_test.cpp tests/upload_throttler_test.cpp tests/client_credits_test.cpp tests/cli_smoke_test.cpp tests/net_smoke_test.cpp tests/framing_test.cpp tests/runtime_test.cpp tests/mock_peer.cpp tests/connection_test.cpp tests/encrypted_stream_socket_test.cpp tests/search_query_test.cpp tests/server_messages_test.cpp tests/mock_server.cpp tests/server_connection_test.cpp tests/udp_framing_test.cpp tests/udp_messages_test.cpp tests/udp_obfuscation_test.cpp tests/udp_socket_test.cpp tests/mock_udp_server.cpp tests/udp_connection_test.cpp tests/c2c_messages_test.cpp tests/c2c_connection_test.cpp tests/upload_session_test.cpp tests/part_file_test.cpp tests/block_allocator_test.cpp tests/aich_checker_test.cpp tests/download_test.cpp tests/app_session_test.cpp tests/app_download_test.cpp tests/live_server_test.cpp tests/live_download_test.cpp tests/live_upload_test.cpp tests/live_kad_test.cpp tests/inbound_listener_test.cpp tests/kad_id_test.cpp tests/kad_routing_test.cpp tests/kad_nodes_dat_test.cpp tests/kad_keywords_test.cpp tests/kad_messages_test.cpp tests/kad_indexed_test.cpp tests/kad_udp_crypto_test.cpp tests/kad_network_test.cpp)
  target_link_libraries(ed2k_tests PRIVATE ed2k_core GTest::gtest GTest::gtest_main ZLIB::ZLIB)
  target_include_directories(ed2k_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  include(GoogleTest)
  gtest_discover_tests(ed2k_tests)
endif()
