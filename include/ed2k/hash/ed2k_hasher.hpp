#pragma once
#include <cstddef>
#include <span>
#include <vector>
#include <filesystem>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/util/error.hpp"
namespace ed2k {
constexpr std::size_t CHUNK_SIZE = 9728000;
enum class HashVariant { Blue, Red };
struct HashResult { FileHash file_hash; std::vector<PartHash> part_hashes; };
// 默认 Red: aMule/eMule 对 PART_SIZE 整数倍文件追加空尾 part MD4("") (字节级对照 aMule 2.3.3
// SendHashsetPacket + 文件哈希, 见 docs/RELEASE-PLAN R0-1 multi-part live)。Blue 仅留作对照/测试。
HashResult hash_bytes(std::span<const std::byte>, HashVariant = HashVariant::Red);
tl::expected<HashResult,std::error_code> hash_file(const std::filesystem::path&, HashVariant = HashVariant::Red);
}
