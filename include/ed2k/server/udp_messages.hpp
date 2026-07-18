#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"            // FileHash/IPv4
#include "ed2k/server/udp_opcodes.hpp"
#include "ed2k/server/search_query.hpp"  // SearchExpr
#include "ed2k/server/messages.hpp"      // P3a: SearchResultItem, SourceEndpoint, FoundSources
namespace ed2k::server {

// C2S encoding: returns payload (caller sets opcode on net::Packet)
std::vector<std::byte> encode_glob_search_req(const SearchExpr&);                       // = serialize_search
std::vector<std::byte> encode_get_sources_req(const FileHash&, std::uint64_t size);      // hash16 + u64 size
std::vector<std::byte> encode_server_status_req(std::uint32_t challenge);               // u32
std::vector<std::byte> encode_server_list_req(IPv4 ip, std::uint16_t port);             // u32 ip + u16 port
std::vector<std::byte> encode_server_desc_req(std::uint32_t challenge);                 // u32

// S2C structures (populated by Task 3 decode)
struct UdpSearchResult { std::vector<SearchResultItem> items; };
struct ServerStat {
  std::uint32_t challenge=0, users=0, files=0;
  std::uint32_t max_users=0, soft_files=0, hard_files=0, udp_flags=0, low_id_users=0;
  std::uint16_t udp_obf_port=0, tcp_obf_port=0;
  std::uint32_t udp_key=0;
};
struct ServerDesc { std::string name, description; };

// S2C decode
tl::expected<UdpSearchResult,std::error_code> decode_glob_search_res(std::span<const std::byte>);
tl::expected<std::vector<FoundSources>,std::error_code> decode_glob_found_sources(std::span<const std::byte>);
tl::expected<ServerStat,std::error_code> decode_server_stat(std::span<const std::byte>, std::uint32_t challenge);
tl::expected<ServerDesc,std::error_code> decode_server_desc(std::span<const std::byte>, std::uint32_t challenge);
tl::expected<ServerIdent,std::error_code> decode_udp_server_ident(std::span<const std::byte>);
tl::expected<std::uint32_t,std::error_code> decode_invalid_low_id(std::span<const std::byte>);
}
