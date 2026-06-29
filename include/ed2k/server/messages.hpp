#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"        // UserHash / FileHash
#include "ed2k/server/search_query.hpp"
namespace ed2k::server {

struct LoginParams {
  UserHash user_hash;
  std::uint16_t client_port = 0;
  std::string nickname;
  std::uint32_t version = 0x3C;            // eDonkey 60
  std::uint32_t server_flags = 0;
};

// C→S 编码：返回 payload（opcode 由调用方设入 net::Packet）
std::vector<std::byte> encode_login(const LoginParams&);
std::vector<std::byte> encode_search(const SearchExpr&);                       // = serialize_search
std::vector<std::byte> encode_get_sources(const FileHash&, std::uint64_t size);
std::vector<std::byte> encode_callback_request(std::uint32_t client_id);
std::vector<std::byte> encode_get_server_list();
}
