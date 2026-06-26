#include "ed2k/hash/ed2k_hasher.hpp"
#include "crypto/md4.hpp"
#include <algorithm>
#include <fstream>
namespace ed2k {
HashResult hash_bytes(std::span<const std::byte> data, HashVariant v){
  HashResult res;
  std::size_t n=data.size(), off=0;
  // 每个 CHUNK 一个 MD4（最后一块可能不足）
  do {
    std::size_t take = std::min(CHUNK_SIZE, n-off);
    res.part_hashes.push_back(MD4Hash::from_bytes(crypto::md4(data.subspan(off,take))));
    off += take;
  } while(off < n);
  // Red：文件为 CHUNK 整数倍（且非空）时追加空块 MD4
  if(v==HashVariant::Red && n>0 && n%CHUNK_SIZE==0)
    res.part_hashes.push_back(MD4Hash::from_bytes(crypto::md4({})));
  if(res.part_hashes.size()==1){
    res.file_hash = res.part_hashes[0];
  } else {
    std::vector<std::byte> concat; concat.reserve(res.part_hashes.size()*16);
    for(auto& p:res.part_hashes) for(auto b:p.bytes()) concat.push_back(b);
    res.file_hash = MD4Hash::from_bytes(crypto::md4(concat));
  }
  return res;
}
tl::expected<HashResult,std::error_code> hash_file(const std::filesystem::path& p, HashVariant v){
  std::error_code ec; auto size=std::filesystem::file_size(p,ec);
  if(ec) return tl::unexpected(make_error_code(errc::io_error));
  std::ifstream f(p, std::ios::binary);
  if(!f) return tl::unexpected(make_error_code(errc::io_error));
  std::vector<std::byte> buf(static_cast<std::size_t>(size));
  if(size>0) f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size));
  if(!f && size>0) return tl::unexpected(make_error_code(errc::io_error));
  return hash_bytes(buf, v);
}
}
