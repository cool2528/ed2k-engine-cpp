#include "ed2k/server/udp_messages.hpp"
#include "ed2k/codec/byte_io.hpp"
namespace ed2k::server {
using codec::ByteWriter;
using codec::ByteReader;
std::vector<std::byte> encode_glob_search_req(const SearchExpr& e){ return serialize_search(e); }
std::vector<std::byte> encode_get_sources_req(const FileHash& h, std::uint64_t size){
  ByteWriter w; w.hash16(h); w.u32(static_cast<std::uint32_t>(size)); return w.take();
}
std::vector<std::byte> encode_server_status_req(std::uint32_t challenge){ ByteWriter w; w.u32(challenge); return w.take(); }
std::vector<std::byte> encode_server_list_req(IPv4 ip, std::uint16_t port){ ByteWriter w; w.u32_be(ip.host()); w.u16(port); return w.take(); }
std::vector<std::byte> encode_server_desc_req(std::uint32_t challenge){ ByteWriter w; w.u32(challenge); return w.take(); }

tl::expected<UdpSearchResult,std::error_code> decode_glob_search_res(std::span<const std::byte> data){
  ByteReader r(data);
  UdpSearchResult out;
  while(r.ok() && r.remaining() > 0){
    SearchResultItem item;
    item.hash = r.hash16();
    item.client_id = r.u32();
    item.port = r.u16();
    std::uint32_t tc = r.u32();
    auto tags = codec::read_taglist(r, tc);
    if(!tags) return tl::unexpected(tags.error());
    item.tags = std::move(*tags);
    for(auto& t : item.tags){
      if(t.name_id == tag::FT_FILENAME && std::holds_alternative<std::string>(t.value))
        item.name = std::get<std::string>(t.value);
      else if(t.name_id == tag::FT_FILESIZE && std::holds_alternative<std::uint64_t>(t.value))
        item.size = std::get<std::uint64_t>(t.value);
    }
    if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
    out.items.push_back(std::move(item));
    if(r.remaining() >= 2){
      std::uint8_t proto = r.u8(), op = r.u8();
      if(!(proto == 0xE3 && op == udpop::GLOBSEARCHRES)) break;      // 非分隔符 → 结束（尾部忽略）
    }
  }
  return out;
}
tl::expected<std::vector<FoundSources>,std::error_code> decode_glob_found_sources(std::span<const std::byte> data){
  ByteReader r(data);
  std::vector<FoundSources> out;
  while(r.ok() && r.remaining() > 0){
    FoundSources fs;
    fs.hash = r.hash16();
    std::uint8_t count = r.u8();
    for(std::uint8_t i=0;i<count && r.ok();++i){
      SourceEndpoint s; s.id = r.u32(); s.port = r.u16();
      fs.sources.push_back(s);
    }
    if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
    out.push_back(std::move(fs));
    if(r.remaining() >= 2){
      std::uint8_t proto = r.u8(), op = r.u8();
      if(!(proto == 0xE3 && op == udpop::GLOBFOUNDSOURCES)) break;
    }
  }
  return out;
}
tl::expected<ServerStat,std::error_code> decode_server_stat(std::span<const std::byte> data, std::uint32_t challenge){
  ByteReader r(data);
  std::size_t size = data.size();
  if(size < 12) return tl::unexpected(make_error_code(errc::buffer_underflow));
  ServerStat st;
  st.challenge = r.u32();
  if(st.challenge != challenge) return tl::unexpected(make_error_code(errc::server_protocol_error));
  st.users = r.u32();
  st.files = r.u32();
  if(size >= 16) st.max_users = r.u32();
  if(size >= 24){ st.soft_files = r.u32(); st.hard_files = r.u32(); }
  if(size >= 28) st.udp_flags = r.u32();
  if(size >= 32) st.low_id_users = r.u32();
  if(size >= 40){ st.udp_obf_port = r.u16(); st.tcp_obf_port = r.u16(); st.udp_key = r.u32(); }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return st;
}
// decode_server_list 复用 P3a messages.cpp 的定义（TCP SERVERLIST 与 UDP SERVER_LIST_RES
// 线格式一致：u8 count + count×(u32 ip + u16 port)；签名与行为完全相同，此处不重复定义以免 ODR 冲突）。
tl::expected<ServerDesc,std::error_code> decode_server_desc(std::span<const std::byte> data, std::uint32_t challenge){
  std::size_t size = data.size();
  if(size < 2) return tl::unexpected(make_error_code(errc::buffer_underflow));
  // peek data[0..1] 作为 u16 LE 判定新格式（不消耗；ByteReader 无 seek）
  std::uint16_t len = std::to_integer<std::uint8_t>(data[0])
                    | (std::uint16_t(std::to_integer<std::uint8_t>(data[1])) << 8);
  ByteReader r(data);
  ServerDesc sd;
  if(size >= 8 && len == INV_SERV_DESC_LEN){
    std::uint32_t got = r.u32();                                      // challenge（data[0..3]，低2字节==0xF0FF）
    if(got != challenge) return tl::unexpected(make_error_code(errc::server_protocol_error));
    std::uint32_t tc = r.u32();
    auto tags = codec::read_taglist(r, tc);
    if(!tags) return tl::unexpected(tags.error());
    for(auto& t : *tags){
      if(t.name_id == tag::ST_SERVERNAME && std::holds_alternative<std::string>(t.value))
        sd.name = std::get<std::string>(t.value);
      else if(t.name_id == tag::ST_DESCRIPTION && std::holds_alternative<std::string>(t.value))
        sd.description = std::get<std::string>(t.value);
    }
  } else {
    sd.description = r.string16();                                   // 旧格式：desc 在前
    sd.name = r.string16();                                          //          name 在后
  }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return sd;
}
tl::expected<std::uint32_t,std::error_code> decode_invalid_low_id(std::span<const std::byte> data){
  ByteReader r(data);
  std::uint32_t id = r.u32();
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return id;
}
}
