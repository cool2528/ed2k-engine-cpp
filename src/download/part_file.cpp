#include "ed2k/download/part_file.hpp"
#include "crypto/md4.hpp"
namespace ed2k::download {
PartFile::PartFile(const std::filesystem::path& path, std::uint64_t size, const FileHash& file_hash, std::vector<PartHash> part_hashes)
  : path_(path), size_(size), file_hash_(file_hash), part_hashes_(std::move(part_hashes)) {
  if(part_hashes_.empty()) part_hashes_.push_back(file_hash_);
  part_done_.assign(part_hashes_.size(), false);
  part_filled_.assign(part_hashes_.size(), 0);
  block_done_.resize(part_hashes_.size());
  if(!std::filesystem::exists(path_)) { std::ofstream c(path_, std::ios::binary); }
  f_.open(path_, std::ios::binary | std::ios::in | std::ios::out);
  for(std::size_t i=0;i<part_hashes_.size();++i){
    std::uint64_t pstart = i*PART_SIZE;
    std::uint64_t pend = std::min((i+1)*PART_SIZE, size_);
    std::uint64_t plen = pend-pstart;
    std::size_t nblk = static_cast<std::size_t>((plen + AICH_BLK - 1)/AICH_BLK);
    block_done_[i].assign(nblk, false);
    std::vector<std::byte> buf(plen);
    f_.seekg(pstart);
    f_.read(reinterpret_cast<char*>(buf.data()), plen);
    if(static_cast<std::uint64_t>(f_.gcount()) == plen){
      crypto::MD4 m; m.update(buf);
      if(PartHash::from_bytes(m.finish()) == part_hashes_[i]){
        part_done_[i] = true; part_filled_[i] = plen;
        std::fill(block_done_[i].begin(), block_done_[i].end(), true);
      }
    }
    f_.clear();
  }
}
bool PartFile::open_for_write() const noexcept { return f_.is_open(); }
std::vector<std::uint32_t> PartFile::missing_parts_peer_has(const std::vector<bool>& peer_parts) const {
  std::vector<std::uint32_t> out;
  for(std::size_t i=0;i<part_done_.size() && i<peer_parts.size();++i)
    if(!part_done_[i] && peer_parts[i]) out.push_back(static_cast<std::uint32_t>(i));
  return out;
}
tl::expected<void,std::error_code> PartFile::write_block(std::uint32_t start, std::uint32_t end, std::span<const std::byte> data){
  std::uint32_t part = start / PART_SIZE;
  if(part >= part_hashes_.size()) return {};
  std::uint64_t pstart = static_cast<std::uint64_t>(part)*PART_SIZE;
  std::uint64_t pend = std::min((static_cast<std::uint64_t>(part)+1)*PART_SIZE, size_);
  std::uint64_t part_len = pend - pstart;
  // 整 part 一次写入兼容路径
  if(start == pstart && end == pend && data.size() == part_len){
    f_.seekp(start);
    f_.write(reinterpret_cast<const char*>(data.data()), data.size());
    part_filled_[part] = part_len;
    std::fill(block_done_[part].begin(), block_done_[part].end(), true);
    if(part_done_[part]) return {};
    crypto::MD4 m; m.update(data);
    if(PartHash::from_bytes(m.finish()) != part_hashes_[part])
      return tl::unexpected(make_error_code(errc::block_corrupt));
    part_done_[part] = true;
    return {};
  }
  // 单 AICH 块写入
  std::size_t ai = static_cast<std::size_t>((start - pstart) / AICH_BLK);
  if(ai >= block_done_[part].size()) return {};
  if(block_done_[part][ai]) return {};   // 幂等:已置位直接成功
  f_.seekp(start);
  f_.write(reinterpret_cast<const char*>(data.data()), data.size());
  block_done_[part][ai] = true;
  // 检查 part 是否所有块置位
  bool all=true;
  for(bool b : block_done_[part]) if(!b){ all=false; break; }
  if(!all) return {};
  if(part_done_[part]) return {};
  // 块满:回读整 part 做 MD4 校验
  std::vector<std::byte> buf(part_len);
  f_.flush();
  f_.seekg(pstart);
  f_.read(reinterpret_cast<char*>(buf.data()), part_len);
  f_.clear();
  if(static_cast<std::uint64_t>(f_.gcount()) != part_len) return {};
  part_filled_[part] = part_len;
  crypto::MD4 m; m.update(buf);
  if(PartHash::from_bytes(m.finish()) != part_hashes_[part])
    return tl::unexpected(make_error_code(errc::block_corrupt));
  part_done_[part] = true;
  return {};
}
bool PartFile::is_block_done(std::size_t part_index, std::size_t aich_index) const noexcept {
  if(part_index >= block_done_.size()) return false;
  if(aich_index >= block_done_[part_index].size()) return false;
  return block_done_[part_index][aich_index];
}
std::vector<std::pair<std::size_t,std::size_t>> PartFile::pending_blocks() const {
  std::vector<std::pair<std::size_t,std::size_t>> out;
  for(std::size_t pi=0; pi<block_done_.size(); ++pi)
    for(std::size_t ai=0; ai<block_done_[pi].size(); ++ai)
      if(!block_done_[pi][ai]) out.emplace_back(pi, ai);
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
