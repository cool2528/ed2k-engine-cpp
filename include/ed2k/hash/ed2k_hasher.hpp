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
HashResult hash_bytes(std::span<const std::byte>, HashVariant = HashVariant::Blue);
tl::expected<HashResult,std::error_code> hash_file(const std::filesystem::path&, HashVariant = HashVariant::Blue);
}
