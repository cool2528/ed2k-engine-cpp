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
// Default Red: aMule/eMule appends an empty trailing part MD4("") for files whose size is an
// exact multiple of PART_SIZE (byte-level match with aMule 2.3.3 SendHashsetPacket + file hash,
// see docs/RELEASE-PLAN R0-1 multi-part live). Blue is kept only for comparison/testing.
HashResult hash_bytes(std::span<const std::byte>, HashVariant = HashVariant::Red);
tl::expected<HashResult,std::error_code> hash_file(const std::filesystem::path&, HashVariant = HashVariant::Red);
}
