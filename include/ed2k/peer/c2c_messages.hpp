#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <array>
#include <utility>
#include <vector>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/peer/c2c_opcodes.hpp"
#include "ed2k/server/opcodes.hpp"   // tag::CT_NAME/CT_VERSION
namespace ed2k::peer {

struct HelloInfo {
  UserHash user_hash;
  std::uint32_t client_id = 0;
  std::uint16_t port = 0;
  std::string nickname;
  std::uint32_t version = 0x3C;
  std::optional<IPv4> server_ip;
  std::optional<std::uint16_t> server_port;
};

// C→C 编码：返回 payload（opcode 由调用方设入 net::Packet）
std::vector<std::byte> encode_hello(const HelloInfo&);
std::vector<std::byte> encode_set_req_file(const FileHash&);
std::vector<std::byte> encode_hashset_request(const FileHash&);
std::vector<std::byte> encode_request_filename(const FileHash&);
std::vector<std::byte> encode_start_upload(const FileHash&);
std::vector<std::byte> encode_request_parts(const FileHash&, std::array<std::uint32_t,3> starts, std::array<std::uint32_t,3> ends);
std::vector<std::byte> encode_end_of_download(const FileHash&);
std::vector<std::byte> encode_cancel_transfer();
}
