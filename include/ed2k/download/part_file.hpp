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
#include "ed2k/hash/aich_hasher.hpp"   // AICH_BLOCK_SIZE / PART_SIZE 单一定义源
namespace ed2k::download {
class PartFile {
 public:
  PartFile(const std::filesystem::path& path, std::uint64_t size, const FileHash& file_hash, std::vector<PartHash> part_hashes);
  bool open_for_write() const noexcept;
  std::vector<std::uint32_t> missing_parts_peer_has(const std::vector<bool>& peer_parts) const;
  tl::expected<void,std::error_code> write_block(std::uint64_t start, std::uint64_t end, std::span<const std::byte> data);
  bool is_block_done(std::size_t part, std::size_t block_in_part) const noexcept;  // per-part
  std::vector<std::pair<std::size_t,std::size_t>> pending_blocks() const;          // (part, block_in_part)
  bool complete() const noexcept;
  std::vector<std::pair<std::uint64_t,std::uint64_t>> gaps() const;
 private:
  std::filesystem::path path_;
  std::uint64_t size_;
  FileHash file_hash_;
  std::vector<PartHash> part_hashes_;
  std::vector<bool> part_done_;
  std::vector<std::uint64_t> part_filled_;  // 每 part 已写入字节数，用于增量组装后触发 MD4 校验
  std::vector<std::vector<bool>> block_done_;  // block_done_[part][block_in_part]; 块不跨 part 边界
  std::fstream f_;

  std::size_t num_parts() const { return part_hashes_.size(); }
  std::uint64_t part_size(std::size_t part) const {
    std::uint64_t base = static_cast<std::uint64_t>(part) * PART_SIZE;
    if (base >= size_) return 0;
    return std::min(PART_SIZE, size_ - base);
  }
  std::size_t blocks_in_part(std::size_t part) const {
    return static_cast<std::size_t>((part_size(part) + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE);
  }
};
}
