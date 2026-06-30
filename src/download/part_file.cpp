#include "ed2k/download/part_file.hpp"
#include "crypto/md4.hpp"
namespace ed2k::download {
PartFile::PartFile(const std::filesystem::path& path, std::uint64_t size, const FileHash& file_hash, std::vector<PartHash> part_hashes)
  : path_(path), size_(size), file_hash_(file_hash), part_hashes_(std::move(part_hashes)) {
  if(part_hashes_.empty()) part_hashes_.push_back(file_hash_);   // 单 part: 文件 hash 即 part hash
  part_done_.assign(part_hashes_.size(), false);
  if(!std::filesystem::exists(path_)) { std::ofstream c(path_, std::ios::binary); }
  f_.open(path_, std::ios::binary | std::ios::in | std::ios::out);
  // 续传:校验已有 part
  for(std::size_t i=0;i<part_hashes_.size();++i){
    std::uint64_t pstart = i*PART_SIZE;
    std::uint64_t pend = std::min((i+1)*PART_SIZE, size_);
    std::vector<std::byte> buf(pend-pstart);
    f_.seekg(pstart);
    f_.read(reinterpret_cast<char*>(buf.data()), pend-pstart);
    if(static_cast<std::uint64_t>(f_.gcount()) == (pend-pstart)){
      crypto::MD4 m; m.update(buf);
      if(PartHash::from_bytes(m.finish()) == part_hashes_[i]) part_done_[i] = true;
    }
    f_.clear();
  }
}
std::vector<std::uint32_t> PartFile::missing_parts_peer_has(const std::vector<bool>& peer_parts) const {
  std::vector<std::uint32_t> out;
  for(std::size_t i=0;i<part_done_.size() && i<peer_parts.size();++i)
    if(!part_done_[i] && peer_parts[i]) out.push_back(static_cast<std::uint32_t>(i));
  return out;
}
tl::expected<void,std::error_code> PartFile::write_block(std::uint32_t start, std::uint32_t end, std::span<const std::byte> data){
  f_.seekp(start);
  f_.write(reinterpret_cast<const char*>(data.data()), data.size());
  std::uint32_t part = start / PART_SIZE;
  if(part < part_hashes_.size()){
    std::uint64_t pstart = static_cast<std::uint64_t>(part)*PART_SIZE;
    std::uint64_t pend = std::min((static_cast<std::uint64_t>(part)+1)*PART_SIZE, size_);
    if(start == pstart && end == pend && data.size() == (pend-pstart)){
      crypto::MD4 m; m.update(data);
      if(PartHash::from_bytes(m.finish()) != part_hashes_[part])
        return tl::unexpected(make_error_code(errc::block_corrupt));
      part_done_[part] = true;
    }
  }
  return {};
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
