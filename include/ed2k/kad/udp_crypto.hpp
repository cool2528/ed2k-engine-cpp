#pragma once

#include <cstdint>
#include <array>
#include <optional>
#include <span>
#include <system_error>
#include <vector>

#include <tl/expected.hpp>

#include "ed2k/core/hash.hpp"
#include "ed2k/kad/kad_id.hpp"

namespace ed2k::kad {

struct KadUdpEncryptOptions {
  std::optional<KadID> target_id;
  std::uint32_t receiver_verify_key = 0;
  std::uint32_t sender_verify_key = 0;
  std::uint16_t random_key_part = 0;
  std::uint8_t marker = 0;
};

struct KadUdpDecodeResult {
  std::vector<std::byte> datagram;
  std::uint32_t receiver_verify_key = 0;
  std::uint32_t sender_verify_key = 0;
  bool encrypted = false;
  bool valid_receiver_key = false;
};

std::uint32_t kad_udp_verify_key(std::uint32_t kad_udp_key, IPv4 target_ip);
std::array<std::byte, 16> kad_id_crypt_bytes(const KadID& id) noexcept;

tl::expected<std::vector<std::byte>, std::error_code>
encode_kad_obfuscated_datagram(std::span<const std::byte> clear_datagram,
                                const KadUdpEncryptOptions& options);

tl::expected<KadUdpDecodeResult, std::error_code>
decode_kad_obfuscated_datagram(std::span<const std::byte> datagram,
                                const KadID& local_id,
                                std::uint32_t local_receiver_verify_key);

} // namespace ed2k::kad
