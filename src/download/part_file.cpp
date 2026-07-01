#include "ed2k/download/part_file.hpp"
#include "crypto/md4.hpp"
namespace ed2k::download {
PartFile::PartFile(const std::filesystem::path& path, std::uint64_t size, const FileHash& file_hash, std::vector<PartHash> part_hashes)
  : path_(path), size_(size), file_hash_(file_hash), part_hashes_(std::move(part_hashes)) {
  if(part_hashes_.empty()) part_hashes_.push_back(file_hash_);
  part_done_.assign(part_hashes_.size(), false);
  part_filled_.assign(part_hashes_.size(), 0);
  // FLAT 整文件块位图: 块大小 AICH_BLK, 块可跨越 part 边界(PART_SIZE 不是 AICH_BLK 整数倍)。
  std::size_t num_blocks = static_cast<std::size_t>((size_ + AICH_BLK - 1) / AICH_BLK);
  block_done_.assign(num_blocks, false);
  if(!std::filesystem::exists(path_)) { std::ofstream c(path_, std::ios::binary); }
  f_.open(path_, std::ios::binary | std::ios::in | std::ios::out);
  // 逐 part 回读 + MD4 校验(续传: 已校验的 part 标 done)
  for(std::size_t i=0;i<part_hashes_.size();++i){
    std::uint64_t pstart = i*PART_SIZE;
    std::uint64_t pend = std::min((i+1)*PART_SIZE, size_);
    std::uint64_t plen = pend-pstart;
    std::vector<std::byte> buf(plen);
    f_.seekg(pstart);
    f_.read(reinterpret_cast<char*>(buf.data()), plen);
    if(static_cast<std::uint64_t>(f_.gcount()) == plen){
      crypto::MD4 m; m.update(buf);
      if(PartHash::from_bytes(m.finish()) == part_hashes_[i]){
        part_done_[i] = true; part_filled_[i] = plen;
      }
    }
    f_.clear();
  }
  // 推导 flat block_done_: 一个块 done 当且仅当它跨越的所有 part 都已 MD4 校验通过。
  // 跨界块(如 global 52 横跨 part0/part1)只有两侧 part 都 done 才算 done,
  // 否则块内仍含未校验字节, 必须重新下载。
  for(std::size_t g=0; g<num_blocks; ++g){
    std::uint64_t bs = g * AICH_BLK;
    std::uint64_t be = std::min(bs + AICH_BLK, size_);
    std::size_t p_first = static_cast<std::size_t>(bs / PART_SIZE);
    std::size_t p_last  = static_cast<std::size_t>((be - 1) / PART_SIZE);
    bool all_done = true;
    for(std::size_t p=p_first; p<=p_last && p<part_done_.size(); ++p){
      if(!part_done_[p]){ all_done=false; break; }
    }
    if(all_done) block_done_[g] = true;
  }
}
bool PartFile::open_for_write() const noexcept { return f_.is_open(); }
std::vector<std::uint32_t> PartFile::missing_parts_peer_has(const std::vector<bool>& peer_parts) const {
  std::vector<std::uint32_t> out;
  for(std::size_t i=0;i<part_done_.size() && i<peer_parts.size();++i)
    if(!part_done_[i] && peer_parts[i]) out.push_back(static_cast<std::uint32_t>(i));
  return out;
}
// 写入一个 flat 整文件块 [start, end)。块可跨越 part 边界: 一次连续写盘, 然后按 part 边界
// 切分累计 part_filled_, 每个 part 字节满即回读整 part 做 MD4 校验。整 part 兼容路径已移除
// (一个整 part 是 53 个 flat 块, 不是单个块)。
tl::expected<void,std::error_code> PartFile::write_block(std::uint32_t start, std::uint32_t end, std::span<const std::byte> data){
  std::size_t global = static_cast<std::size_t>(static_cast<std::uint64_t>(start) / AICH_BLK);
  if(global >= block_done_.size()) return {};
  if(block_done_[global]) return {};   // 幂等: 已置位直接成功, 不重复写盘/校验/计数
  f_.seekp(start);
  f_.write(reinterpret_cast<const char*>(data.data()), data.size());
  block_done_[global] = true;
  // 按 part 边界切分 [start, end) 累计 part_filled_ 并触发 MD4。
  std::uint64_t cur = start;
  std::uint64_t finish = end;
  while(cur < finish){
    std::size_t part = static_cast<std::size_t>(cur / PART_SIZE);
    if(part >= part_done_.size()) break;
    std::uint64_t pstart = static_cast<std::uint64_t>(part) * PART_SIZE;
    std::uint64_t pend = std::min((static_cast<std::uint64_t>(part)+1)*PART_SIZE, size_);
    std::uint64_t seg_end = std::min(finish, pend);
    if(!part_done_[part]) part_filled_[part] += (seg_end - cur);
    cur = seg_end;
    // 该 part 字节满: 回读整 part 做 MD4 校验
    if(!part_done_[part] && part_filled_[part] == (pend - pstart)){
      std::vector<std::byte> buf(pend - pstart);
      f_.flush();
      f_.seekg(pstart);
      f_.read(reinterpret_cast<char*>(buf.data()), pend - pstart);
      f_.clear();
      if(static_cast<std::uint64_t>(f_.gcount()) != (pend - pstart)) return tl::unexpected(make_error_code(errc::io_error));
      crypto::MD4 m; m.update(buf);
      if(PartHash::from_bytes(m.finish()) != part_hashes_[part])
        return tl::unexpected(make_error_code(errc::block_corrupt));
      part_done_[part] = true;
    }
  }
  return {};
}
bool PartFile::is_block_done(std::size_t global_block) const noexcept {
  if(global_block >= block_done_.size()) return false;
  return block_done_[global_block];
}
std::vector<std::size_t> PartFile::pending_blocks() const {
  std::vector<std::size_t> out;
  for(std::size_t g=0; g<block_done_.size(); ++g)
    if(!block_done_[g]) out.push_back(g);
  return out;
}
bool PartFile::complete() const noexcept {
  for(bool d : part_done_) if(!d) return false;
  return true;
}
std::vector<std::pair<std::uint64_t,std::uint64_t>> PartFile::gaps() const {
  std::vector<std::pair<std::uint64_t,std::uint64_t>> out;
  for(std::size_t i=0;i<part_done_.size();++i){
    if(!part_done_[i]){
      std::uint64_t pstart = i*PART_SIZE;
      std::uint64_t pend = std::min((i+1)*PART_SIZE, size_);
      out.emplace_back(pstart, pend);
    }
  }
  return out;
}
}
