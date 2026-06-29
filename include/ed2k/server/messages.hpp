#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"        // UserHash / FileHash / MD4Hash / IPv4
#include "ed2k/codec/tag.hpp"        // codec::Tag
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

// S→C 解码结构
struct IdChange        { std::uint32_t id=0, flags=0; bool high_id() const { return id>=0x1000000u; } };
struct ServerStatus    { std::uint32_t users=0, files=0; };
struct ServerIdent     { MD4Hash hash; IPv4 ip; std::uint16_t port=0; std::string name, description; };
struct CallbackRequested{ IPv4 ip; std::uint16_t port=0; };
struct SourceEndpoint  { std::uint32_t id=0; std::uint16_t port=0;
                         bool low_id() const { return id<0x1000000u; } };
struct FoundSources    { FileHash hash; std::vector<SourceEndpoint> sources; };
struct SearchResultItem{
  FileHash hash; std::uint32_t client_id=0; std::uint16_t port=0;
  std::string name; std::uint64_t size=0;
  std::vector<codec::Tag> tags;
};

tl::expected<IdChange,std::error_code>                      decode_id_change(std::span<const std::byte>);
tl::expected<ServerStatus,std::error_code>                  decode_server_status(std::span<const std::byte>);
tl::expected<std::string,std::error_code>                   decode_server_message(std::span<const std::byte>);
tl::expected<ServerIdent,std::error_code>                   decode_server_ident(std::span<const std::byte>);
tl::expected<std::vector<std::pair<IPv4,std::uint16_t>>,std::error_code>
                                                            decode_server_list(std::span<const std::byte>);
tl::expected<CallbackRequested,std::error_code>             decode_callback_requested(std::span<const std::byte>);
tl::expected<std::vector<SearchResultItem>,std::error_code> decode_search_result(std::span<const std::byte>);
tl::expected<FoundSources,std::error_code>                  decode_found_sources(std::span<const std::byte>);
}
