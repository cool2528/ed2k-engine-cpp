#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>
#include <vector>

#include <tl/expected.hpp>

namespace ed2k::net {

enum class ServerUdpObfuscationDirection {
  client_to_server,
  server_to_client,
};

struct ServerUdpObfuscationOptions {
  std::uint32_t base_key = 0;
  ServerUdpObfuscationDirection direction = ServerUdpObfuscationDirection::client_to_server;
  std::uint16_t random_key_part = 0;
  std::uint8_t marker = 0;
};

struct ServerUdpObfuscationDecodeOptions {
  std::uint32_t base_key = 0;
  ServerUdpObfuscationDirection direction = ServerUdpObfuscationDirection::server_to_client;
};

struct ServerUdpObfuscationDecodeResult {
  std::vector<std::byte> datagram;
  bool encrypted = false;
};

tl::expected<std::vector<std::byte>, std::error_code>
encode_server_udp_obfuscated_datagram(std::span<const std::byte> clear_datagram,
                                      const ServerUdpObfuscationOptions& options);

tl::expected<ServerUdpObfuscationDecodeResult, std::error_code>
decode_server_udp_obfuscated_datagram(std::span<const std::byte> datagram,
                                      const ServerUdpObfuscationDecodeOptions& options);

} // namespace ed2k::net

