#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"
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
// 两级平衡二叉 Merkle 子树（对照 aMule SHAHashSet.cpp CAICHHashTree 构造 + FindHash + ReCalculateHash）。
//   data_size: 本节点覆盖的数据长度
//   base_size: 叶层基大小（顶层 PART_SIZE / 底层 AICH_BLOCK_SIZE）
//   is_left:   m_bIsLeftBranch（左子=true，右子=false；根=true）
Digest build_subtree(std::span<const std::byte> data,
                     std::uint64_t data_size, std::uint64_t base_size, bool is_left) {
  if (data_size <= base_size) {
    // 叶节点：SHA1(原始块数据)（aMule FindHash:113 「m_nDataSize <= m_nBaseSize 即末层」）
    return crypto::sha1(data.first(static_cast<std::size_t>(data_size)));
  }
  // 平衡二叉分裂（aMule FindHash:118-120）：
  //   nBlocks = ceil(data_size / base_size)
  //   nLeft   = (is_left ? ceil(nBlocks/2) : floor(nBlocks/2)) * base_size
  std::uint64_t nBlocks = data_size / base_size + ((data_size % base_size != 0) ? 1 : 0);
  std::uint64_t nLeft   = (((is_left ? nBlocks + 1 : nBlocks) / 2)) * base_size;
  std::uint64_t nRight  = data_size - nLeft;
  // 子节点 baseSize 切换（aMule FindHash:128,138）：nLeft/nRight <= PARTSIZE → EMBLOCKSIZE
  std::uint64_t base_left  = (nLeft  <= PART_SIZE) ? AICH_BLOCK_SIZE : PART_SIZE;
  std::uint64_t base_right = (nRight <= PART_SIZE) ? AICH_BLOCK_SIZE : PART_SIZE;
  Digest left_hash  = build_subtree(data.first(static_cast<std::size_t>(nLeft)),
                                     nLeft, base_left, true);
  Digest right_hash = build_subtree(data.subspan(static_cast<std::size_t>(nLeft)),
                                     nRight, base_right, false);
  return sha1_concat(left_hash, right_hash);
}
} // namespace

AICHHash aich_hash_bytes(std::span<const std::byte> data){
  // 两级 Merkle 树：顶层以 PARTSIZE 为基、part 子树以 EMBLOCKSIZE 为基，块不跨 part 边界。
  std::uint64_t n = static_cast<std::uint64_t>(data.size());
  if (n == 0) return AICHHash::from_bytes(crypto::sha1({}));
  // 根 baseSize（aMule SetFileSize）：n <= PARTSIZE → EMBLOCKSIZE，否则 PARTSIZE。根 isLeft=true。
  std::uint64_t root_base = (n <= PART_SIZE) ? AICH_BLOCK_SIZE : PART_SIZE;
  return AICHHash::from_bytes(build_subtree(data, n, root_base, true));
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
