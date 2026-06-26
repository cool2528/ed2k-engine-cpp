#pragma once
#include <cstddef>
#include <span>
#include <filesystem>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/util/error.hpp"
namespace ed2k {
constexpr std::size_t AICH_BLOCK_SIZE = 184320;
AICHHash aich_hash_bytes(std::span<const std::byte>);
tl::expected<AICHHash,std::error_code> aich_hash_file(const std::filesystem::path&);
}
