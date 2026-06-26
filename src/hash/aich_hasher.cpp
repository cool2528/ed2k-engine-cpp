#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"  // CHUNK_SIZE
#include "crypto/sha1.hpp"
#include <fstream>
#include <vector>
namespace ed2k {
namespace {
using Digest = std::array<std::byte,20>;
Digest sha1_concat(const Digest& l, const Digest& r){
  std::array<std::byte,40> buf; for(int i=0;i<20;++i){buf[i]=l[i]; buf[20+i]=r[i];}
  return crypto::sha1(buf);
}
// 把一组叶子两两 Merkle 归并为根（奇数末位直接上提）
Digest merkle_root(std::vector<Digest> level){
  if(level.empty()) return crypto::sha1({}); // 不会发生，留作保护
  while(level.size()>1){
    std::vector<Digest> next;
    for(std::size_t i=0;i<level.size();i+=2){
      if(i+1<level.size()) next.push_back(sha1_concat(level[i],level[i+1]));
      else next.push_back(level[i]);
    }
    level.swap(next);
  }
  return level[0];
}
// 计算单个 chunk（<=9.28MB）的 chunk 哈希：按 184320B 小块 SHA-1 → Merkle
Digest chunk_hash(std::span<const std::byte> chunk){
  std::vector<Digest> leaves;
  std::size_t off=0, n=chunk.size();
  do {
    std::size_t take=std::min(AICH_BLOCK_SIZE, n-off);
    leaves.push_back(crypto::sha1(chunk.subspan(off,take)));
    off+=take;
  } while(off<n);
  return merkle_root(std::move(leaves));
}
}
AICHHash aich_hash_bytes(std::span<const std::byte> data){
  std::vector<Digest> chunk_hashes;
  std::size_t off=0, n=data.size();
  do {
    std::size_t take=std::min(CHUNK_SIZE, n-off);
    chunk_hashes.push_back(chunk_hash(data.subspan(off,take)));
    off+=take;
  } while(off<n);
  return AICHHash::from_bytes(merkle_root(std::move(chunk_hashes)));
}
tl::expected<AICHHash,std::error_code> aich_hash_file(const std::filesystem::path& p){
  std::error_code ec; auto size=std::filesystem::file_size(p,ec);
  if(ec) return tl::unexpected(make_error_code(errc::io_error));
  std::ifstream f(p,std::ios::binary); if(!f) return tl::unexpected(make_error_code(errc::io_error));
  std::vector<std::byte> buf(static_cast<std::size_t>(size));
  if(size>0) f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size));
  return aich_hash_bytes(buf);
}
}
