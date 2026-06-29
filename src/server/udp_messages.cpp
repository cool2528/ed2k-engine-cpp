#include "ed2k/server/udp_messages.hpp"
#include "ed2k/codec/byte_io.hpp"
namespace ed2k::server {
using codec::ByteWriter;
std::vector<std::byte> encode_glob_search_req(const SearchExpr& e){ return serialize_search(e); }
std::vector<std::byte> encode_get_sources_req(const FileHash& h, std::uint64_t size){
  ByteWriter w; w.hash16(h); w.u32(static_cast<std::uint32_t>(size)); return w.take();
}
std::vector<std::byte> encode_server_status_req(std::uint32_t challenge){ ByteWriter w; w.u32(challenge); return w.take(); }
std::vector<std::byte> encode_server_list_req(IPv4 ip, std::uint16_t port){ ByteWriter w; w.u32(ip.value); w.u16(port); return w.take(); }
std::vector<std::byte> encode_server_desc_req(std::uint32_t challenge){ ByteWriter w; w.u32(challenge); return w.take(); }
}
