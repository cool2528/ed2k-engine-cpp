#pragma once
#include <chrono>
#include <cstdint>
#include <array>
#include <system_error>
#include <utility>
#include <vector>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/net/connection.hpp"
#include "ed2k/peer/c2c_messages.hpp"
namespace ed2k::peer {
class C2CConnection {
 public:
  explicit C2CConnection(boost::asio::any_io_executor ex);
  explicit C2CConnection(boost::asio::ip::tcp::socket&& s) : conn_(std::move(s)) {}
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    connect(IPv4 ip, std::uint16_t port, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<HelloInfo,std::error_code>>
    handshake(const HelloInfo& mine, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<FileStatus,std::error_code>>
    request_file(const FileHash&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::vector<PartHash>,std::error_code>>
    request_hashset(const FileHash&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::string,std::error_code>>
    request_filename(const FileHash&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    start_upload(const FileHash&, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::vector<Block>,std::error_code>>
    request_blocks(const FileHash&, std::array<std::uint32_t,3> starts, std::array<std::uint32_t,3> ends, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::vector<Block>,std::error_code>>
    request_blocks_i64(const FileHash&, std::array<std::uint64_t,3> starts, std::array<std::uint64_t,3> ends, std::chrono::milliseconds timeout);
  boost::asio::awaitable<tl::expected<std::vector<std::array<std::byte,20>>,std::error_code>>
    request_aich_proof(const FileHash&, std::uint16_t block_index, std::chrono::milliseconds timeout);
  void close() noexcept;
 private:
  boost::asio::awaitable<tl::expected<ed2k::net::Packet,std::error_code>>
    pump_until(std::uint8_t want, std::chrono::milliseconds budget);
  ed2k::net::Connection conn_;
};
}
