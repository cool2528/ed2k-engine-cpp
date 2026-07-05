#pragma once

#include <cstdint>
#include <span>
#include <system_error>
#include <vector>

#include <tl/expected.hpp>

#include "ed2k/kad/routing_table.hpp"

namespace ed2k::kad {

// Little-endian u32 writes the file bytes "KAD2".
inline constexpr std::uint32_t nodes_dat_magic = 0x3244414b;

std::vector<std::byte> write_nodes_dat(std::span<const Contact> contacts);
tl::expected<std::vector<Contact>, std::error_code> parse_nodes_dat(std::span<const std::byte> data);

} // namespace ed2k::kad
