#include "ed2k/download/part_file.hpp"
#include "crypto/md4.hpp"
namespace ed2k::download {
PartFile::PartFile(const std::filesystem::path& path, std::uint64_t size, const FileHash& file_hash, std::vector<PartHash> part_hashes)
  : path_(path), size_(size), file_hash_(file_hash), part_hashes_(std::move(part_hashes)) {
  if(part_hashes_.empty()) part_hashes_.push_back(file_hash_);
  part_done_.assign(part_hashes_.size(), false);
  part_filled_.assign(part_hashes_.size(), 0);
  // per-part 块位图: 每 part ceil(part_size/AICH_BLOCK_SIZE) 块, 块不跨 part 边界。
  block_done_.resize(part_hashes_.size());
  for(std::size_t p=0;p<part_hashes_.size();++p)
    block_done_[p].assign(blocks_in_part(p), false);
  if(!std::filesystem::exists(path_)) { std::ofstream c(path_, std::ios::binary); }
  f_.open(path_, std::ios::binary | std::ios::in | std::ios::out);
  // 逐 part 回读 + MD4 校验(续传: 已校验的 part 标 done)
  for(std::size_t i=0;i<part_hashes_.size();++i){
    std::uint64_t pstart = i*PART_SIZE;
    std::uint64_t pend = std::min((i+1)*PART_SIZE, size_);
    std::uint64_t plen = pend-pstart;
    if(plen==0) continue;
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
  // 推导 per-part block_done_: 一个 part 的 MD4 校验通过 → 该 part 所有块均 done。
  // (块不跨 part: 无需跨界联合判定。)
  for(std::size_t p=0;p<part_hashes_.size();++p){
    if(part_done_[p]) block_done_[p].assign(blocks_in_part(p), true);
  }
}
bool PartFile::open_for_write() const noexcept { return f_.is_open(); }
std::vector<std::uint32_t> PartFile::missing_parts_peer_has(const std::vector<bool>& peer_parts) const {
  std::vector<std::uint32_t> out;
  for(std::size_t i=0;i<part_done_.size() && i<peer_parts.size();++i)
    if(!part_done_[i] && peer_parts[i]) out.push_back(static_cast<std::uint32_t>(i));
  return out;
}
// 写入一个 per-part 块 [start, end)。块绝不跨 part 边界(per-part 模型):
//   part = start/PART_SIZE, block_in_part = (start%PART_SIZE)/AICH_BLOCK_SIZE。
// 一次连续写盘, 然后按 part 边界累计 part_filled_ (per-part 块恒落单 part, 循环退化为单段),
// 该 part 字节满即回读整 part 做 MD4 校验。
tl::expected<void,std::error_code> PartFile::write_block(std::uint64_t start, std::uint64_t end, std::span<const std::byte> data){
  std::size_t part = static_cast<std::size_t>(start / PART_SIZE);
  std::size_t bip  = static_cast<std::size_t>((start % PART_SIZE) / AICH_BLOCK_SIZE);
  if(part >= block_done_.size() || bip >= block_done_[part].size()) return {};
  if(block_done_[part][bip]) return {};   // 幂等: 已置位直接成功, 不重复写盘/校验/计数
  f_.seekp(start);
  f_.write(reinterpret_cast<const char*>(data.data()), data.size());
  block_done_[part][bip] = true;
  // 按 part 边界切分 [start, end) 累计 part_filled_ 并触发 MD4 (per-part 块恒单 part)。
  std::uint64_t cur = start;
  std::uint64_t finish = end;
  while(cur < finish){
    std::size_t p = static_cast<std::size_t>(cur / PART_SIZE);
    if(p >= part_done_.size()) break;
    std::uint64_t pstart = static_cast<std::uint64_t>(p) * PART_SIZE;
    std::uint64_t pend = std::min((static_cast<std::uint64_t>(p)+1)*PART_SIZE, size_);
    std::uint64_t seg_end = std::min(finish, pend);
    if(!part_done_[p]) part_filled_[p] += (seg_end - cur);
    cur = seg_end;
    // 该 part 字节满: 回读整 part 做 MD4 校验
    if(!part_done_[p] && part_filled_[p] == (pend - pstart)){
      std::vector<std::byte> buf(pend - pstart);
      f_.flush();
      f_.seekg(pstart);
      f_.read(reinterpret_cast<char*>(buf.data()), pend - pstart);
      f_.clear();
      if(static_cast<std::uint64_t>(f_.gcount()) != (pend - pstart)) return tl::unexpected(make_error_code(errc::io_error));
      crypto::MD4 m; m.update(buf);
      if(PartHash::from_bytes(m.finish()) != part_hashes_[p])
        return tl::unexpected(make_error_code(errc::block_corrupt));
      part_done_[p] = true;
    }
  }
  return {};
}
bool PartFile::is_block_done(std::size_t part, std::size_t block_in_part) const noexcept {
  if(part >= block_done_.size() || block_in_part >= block_done_[part].size()) return false;
  return block_done_[part][block_in_part];
}
std::vector<std::pair<std::size_t,std::size_t>> PartFile::pending_blocks() const {
  std::vector<std::pair<std::size_t,std::size_t>> out;
  for(std::size_t p=0; p<block_done_.size(); ++p)
    for(std::size_t b=0; b<block_done_[p].size(); ++b)
      if(!block_done_[p][b]) out.emplace_back(p, b);
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
