#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <utility>
#include <vector>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
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
  // P4c-3 M3: 异步写盘。状态(block_done_/part_filled_/part_done_) 仅在网络线程变更;
  // f_ 写/readback + MD4 经 disk_ex 卸载 (单 disk 线程串行 f_, 无竞态)。
  // disk_ex == 网络线程 ex 时退化为 post(net) 同步等效 (测试默认路径)。
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    write_block_async(std::uint64_t start, std::uint64_t end, std::span<const std::byte> data,
                      boost::asio::any_io_executor disk_ex);
  bool is_block_done(std::size_t part, std::size_t block_in_part) const noexcept;  // per-part
  std::vector<std::pair<std::size_t,std::size_t>> pending_blocks() const;          // (part, block_in_part)
  bool complete() const noexcept;
  std::vector<std::pair<std::uint64_t,std::uint64_t>> gaps() const;
 private:
  std::filesystem::path path_;
  std::filesystem::path met_path_;   // path_ + ".part.met" (P4c-3 M2 续传持久化)
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
  // P4c-3 M2: .part.met 续传。met-first 恢复 (避整文件重哈希, D1); 失败/陈旧回退 rehash_all。
  bool try_load_met();           // 解析 .part.met → 恢复 part_done_/block_done_; 返回是否成功应用
  void rehash_all();             // 回退路径: 逐 part 回读 + MD4 校验 (P4a 原续传逻辑)
  void save_met() const;         // 把当前 gaps() 落盘 .part.met (part 完成时调用)
};
}
