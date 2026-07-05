#pragma once

#include <cstdint>
#include <filesystem>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <tl/expected.hpp>

namespace ed2k::infra {

struct StatisticsSnapshot {
  std::uint64_t uploaded_bytes = 0;
  std::uint64_t downloaded_bytes = 0;
  std::uint64_t server_connections = 0;
  std::uint64_t failed_connections = 0;
  std::uint64_t kad_packets_sent = 0;
  std::uint64_t sources_seen = 0;
  std::uint64_t files_completed = 0;

  bool operator==(const StatisticsSnapshot&) const = default;
};

class Statistics {
 public:
  static tl::expected<Statistics, std::error_code> load(const std::filesystem::path& path);

  void add_uploaded_bytes(std::uint64_t bytes) noexcept;
  void add_downloaded_bytes(std::uint64_t bytes) noexcept;
  void add_server_connection(bool success) noexcept;
  void add_kad_packet_sent(std::uint64_t count = 1) noexcept;
  void add_source_seen(std::uint64_t count = 1) noexcept;
  void add_file_completed(std::uint64_t count = 1) noexcept;

  const StatisticsSnapshot& session() const noexcept { return session_; }
  const StatisticsSnapshot& cumulative() const noexcept { return cumulative_; }

  tl::expected<void, std::error_code> save(const std::filesystem::path& path) const;
  boost::asio::awaitable<tl::expected<void, std::error_code>>
  async_flush(const std::filesystem::path& path, boost::asio::any_io_executor disk_executor) const;

 private:
  StatisticsSnapshot session_;
  StatisticsSnapshot cumulative_;
};

} // namespace ed2k::infra
