#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <utility>
#include <vector>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/util/error.hpp"
namespace ed2k::download {
constexpr std::uint64_t PART_SIZE = 9728000;
constexpr std::uint64_t AICH_BLK = 184320;   // = AICH_BLOCK_SIZE, 见 block_allocator.hpp
class PartFile {
 public:
  PartFile(const std::filesystem::path& path, std::uint64_t size, const FileHash& file_hash, std::vector<PartHash> part_hashes);
  bool open_for_write() const noexcept;
  std::vector<std::uint32_t> missing_parts_peer_has(const std::vector<bool>& peer_parts) const;
  tl::expected<void,std::error_code> write_block(std::uint32_t start, std::uint32_t end, std::span<const std::byte> data);
  bool is_block_done(std::size_t part_index, std::size_t aich_index) const noexcept;
  std::vector<std::pair<std::size_t,std::size_t>> pending_blocks() const;
  bool complete() const noexcept;
  std::vector<std::pair<std::uint64_t,std::uint64_t>> gaps() const;
 private:
  std::filesystem::path path_;
  std::uint64_t size_;
  FileHash file_hash_;
  std::vector<PartHash> part_hashes_;
  std::vector<bool> part_done_;
  std::vector<std::uint64_t> part_filled_;  // 每 part 已写入字节数，用于增量组装后触发 MD4 校验
  std::vector<std::vector<bool>> block_done_;     // 每 part 的 AICH 块位图
  std::fstream f_;
};
}
