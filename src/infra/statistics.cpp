#include "ed2k/infra/statistics.hpp"

#include <fstream>
#include <utility>
#include <vector>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::infra {
namespace {
namespace asio = boost::asio;
constexpr std::uint32_t statistics_magic = 0x41543245; // E2TA
constexpr std::uint16_t statistics_version = 1;

std::vector<std::byte> read_all(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  in.seekg(0, std::ios::end);
  const auto size = in.tellg();
  in.seekg(0, std::ios::beg);
  if (size <= 0) {
    return {};
  }
  std::vector<std::byte> out(static_cast<std::size_t>(size));
  in.read(reinterpret_cast<char*>(out.data()), size);
  if (!in) {
    return {};
  }
  return out;
}

void write_snapshot(codec::ByteWriter& w, const StatisticsSnapshot& s) {
  w.u64(s.uploaded_bytes);
  w.u64(s.downloaded_bytes);
  w.u64(s.server_connections);
  w.u64(s.failed_connections);
  w.u64(s.kad_packets_sent);
  w.u64(s.sources_seen);
  w.u64(s.files_completed);
}

tl::expected<StatisticsSnapshot, std::error_code> read_snapshot(codec::ByteReader& r) {
  StatisticsSnapshot s;
  s.uploaded_bytes = r.u64();
  s.downloaded_bytes = r.u64();
  s.server_connections = r.u64();
  s.failed_connections = r.u64();
  s.kad_packets_sent = r.u64();
  s.sources_seen = r.u64();
  s.files_completed = r.u64();
  if (!r.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  return s;
}

tl::expected<void, std::error_code> save_snapshot(const std::filesystem::path& path,
                                                  const StatisticsSnapshot& snapshot) {
  codec::ByteWriter w;
  w.u32(statistics_magic);
  w.u16(statistics_version);
  write_snapshot(w, snapshot);
  const auto bytes = w.take();

  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return tl::unexpected(make_error_code(errc::io_error));
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (!out) {
    return tl::unexpected(make_error_code(errc::io_error));
  }
  return {};
}
} // namespace

tl::expected<Statistics, std::error_code> Statistics::load(const std::filesystem::path& path) {
  const auto bytes = read_all(path);
  if (bytes.empty()) {
    return tl::unexpected(make_error_code(errc::io_error));
  }
  codec::ByteReader r(bytes);
  const auto magic = r.u32();
  const auto version = r.u16();
  if (!r.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (magic != statistics_magic) {
    return tl::unexpected(make_error_code(errc::bad_magic));
  }
  if (version != statistics_version) {
    return tl::unexpected(make_error_code(errc::unsupported_version));
  }

  auto snapshot = read_snapshot(r);
  if (!snapshot) {
    return tl::unexpected(snapshot.error());
  }
  Statistics stats;
  stats.cumulative_ = *snapshot;
  return stats;
}

void Statistics::add_uploaded_bytes(std::uint64_t bytes) noexcept {
  session_.uploaded_bytes += bytes;
  cumulative_.uploaded_bytes += bytes;
}

void Statistics::add_downloaded_bytes(std::uint64_t bytes) noexcept {
  session_.downloaded_bytes += bytes;
  cumulative_.downloaded_bytes += bytes;
}

void Statistics::add_server_connection(bool success) noexcept {
  ++session_.server_connections;
  ++cumulative_.server_connections;
  if (!success) {
    ++session_.failed_connections;
    ++cumulative_.failed_connections;
  }
}

void Statistics::add_kad_packet_sent(std::uint64_t count) noexcept {
  session_.kad_packets_sent += count;
  cumulative_.kad_packets_sent += count;
}

void Statistics::add_source_seen(std::uint64_t count) noexcept {
  session_.sources_seen += count;
  cumulative_.sources_seen += count;
}

void Statistics::add_file_completed(std::uint64_t count) noexcept {
  session_.files_completed += count;
  cumulative_.files_completed += count;
}

tl::expected<void, std::error_code> Statistics::save(const std::filesystem::path& path) const {
  return save_snapshot(path, cumulative_);
}

asio::awaitable<tl::expected<void, std::error_code>>
Statistics::async_flush(const std::filesystem::path& path, asio::any_io_executor disk_executor) const {
  const auto caller = co_await asio::this_coro::executor;
  const auto snapshot = cumulative_;
  co_await asio::post(disk_executor, asio::bind_executor(disk_executor, asio::use_awaitable));
  auto result = save_snapshot(path, snapshot);
  co_await asio::post(caller, asio::bind_executor(caller, asio::use_awaitable));
  co_return result;
}

} // namespace ed2k::infra
