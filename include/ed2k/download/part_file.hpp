#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <vector>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/share/known_file.hpp"
#include "ed2k/util/error.hpp"
#include "ed2k/hash/aich_hasher.hpp"   // AICH_BLOCK_SIZE / PART_SIZE single source of truth
namespace ed2k::download {
class PartFile {
 public:
  PartFile(const std::filesystem::path& path, std::uint64_t size, const FileHash& file_hash, std::vector<PartHash> part_hashes);
  ~PartFile();
  PartFile(const PartFile&) = delete;
  PartFile& operator=(const PartFile&) = delete;
  PartFile(PartFile&&) noexcept;
  PartFile& operator=(PartFile&&) noexcept;

  bool open_for_write() const noexcept;
  std::vector<std::uint32_t> missing_parts_peer_has(const std::vector<bool>& peer_parts) const;
  tl::expected<void,std::error_code> write_block(std::uint64_t start, std::uint64_t end, std::span<const std::byte> data);
  // P4c-3 M3: async disk write. State (block_done_/part_filled_/part_done_) is only mutated on the
  // network thread; f_ write/readback + MD4 are offloaded via disk_ex (single disk thread serializes f_, no races).
  // When disk_ex == network thread ex, degrades to post(net) synchronous equivalent (default test path).
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    write_block_async(std::uint64_t start, std::uint64_t end, std::span<const std::byte> data,
                      boost::asio::any_io_executor disk_ex);
  bool is_block_done(std::size_t part, std::size_t block_in_part) const noexcept;  // per-part
  std::vector<std::pair<std::size_t,std::size_t>> pending_blocks() const;          // (part, block_in_part)
  bool complete() const noexcept;
  std::vector<std::pair<std::uint64_t,std::uint64_t>> gaps() const;
  tl::expected<ed2k::share::KnownFile,std::error_code> to_known_file() const;
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
}
