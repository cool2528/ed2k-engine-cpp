#include "ed2k/server/messages.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/codec/tag.hpp"        // Tag, write_taglist
namespace ed2k::server {
using codec::ByteWriter;
using codec::ByteReader;
using codec::Tag;

namespace {
Tag string_tag(std::uint8_t id, std::string_view v){ Tag t; t.name_id=id; t.value=std::string(v); return t; }
Tag u32_tag(std::uint8_t id, std::uint32_t v){ Tag t; t.name_id=id; t.value=std::uint64_t(v); return t; }
}

std::vector<std::byte> encode_login(const LoginParams& p){
  ByteWriter w;
  w.hash16(p.user_hash);
  w.u32(0);                                          // client ID = 0 (登录时)
  w.u16(p.client_port);
  std::vector<Tag> tags;
  tags.push_back(string_tag(tag::CT_NAME, p.nickname));
  tags.push_back(u32_tag(tag::CT_VERSION, p.version));
  tags.push_back(u32_tag(tag::CT_SERVER_FLAGS, p.server_flags));
  w.u32(static_cast<std::uint32_t>(tags.size()));
  codec::write_taglist(w, tags);
  return w.take();
}
std::vector<std::byte> encode_search(const SearchExpr& e){ return serialize_search(e); }
std::vector<std::byte> encode_get_sources(const FileHash& h, std::uint64_t size){
  ByteWriter w; w.hash16(h); w.u32(static_cast<std::uint32_t>(size)); return w.take();
}
std::vector<std::byte> encode_callback_request(std::uint32_t client_id){
  ByteWriter w; w.u32(client_id); return w.take();
}
std::vector<std::byte> encode_get_server_list(){ return {}; }

tl::expected<IdChange,std::error_code> decode_id_change(std::span<const std::byte> data){
  ByteReader r(data);
  IdChange ic; ic.id = r.u32();
  if(r.remaining() >= 4) ic.flags = r.u32();      // 可选 flags
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return ic;
}
tl::expected<ServerStatus,std::error_code> decode_server_status(std::span<const std::byte> data){
  ByteReader r(data);
  ServerStatus s; s.users = r.u32(); s.files = r.u32();
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return s;
}
tl::expected<std::string,std::error_code> decode_server_message(std::span<const std::byte> data){
  ByteReader r(data);
  std::string msg = r.string16();
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return msg;
}
tl::expected<ServerIdent,std::error_code> decode_server_ident(std::span<const std::byte> data){
  ByteReader r(data);
  ServerIdent si;
  si.hash = r.hash16();
  si.ip = IPv4::from_host(r.u32_be());
  si.port = r.u16();
  std::uint32_t tc = r.u32();
  auto tags = codec::read_taglist(r, tc);
  if(!tags) return tl::unexpected(tags.error());
  for(auto& t : *tags){
    if(t.name_id == tag::ST_SERVERNAME && std::holds_alternative<std::string>(t.value))
      si.name = std::get<std::string>(t.value);
    else if(t.name_id == tag::ST_DESCRIPTION && std::holds_alternative<std::string>(t.value))
      si.description = std::get<std::string>(t.value);
  }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return si;
}
tl::expected<std::vector<std::pair<IPv4,std::uint16_t>>,std::error_code>
decode_server_list(std::span<const std::byte> data){
  ByteReader r(data);
  std::uint8_t count = r.u8();
  std::vector<std::pair<IPv4,std::uint16_t>> out; out.reserve(count);
  for(std::uint8_t i=0;i<count && r.ok();++i){
    IPv4 ip = IPv4::from_host(r.u32_be());
    std::uint16_t port = r.u16();
    out.emplace_back(ip, port);
  }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return out;
}
tl::expected<CallbackRequested,std::error_code> decode_callback_requested(std::span<const std::byte> data){
  ByteReader r(data);
  CallbackRequested cr;
  cr.ip = IPv4::from_host(r.u32_be());
  cr.port = r.u16();
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return cr;
}
tl::expected<std::vector<SearchResultItem>,std::error_code>
decode_search_result(std::span<const std::byte> data){
  ByteReader r(data);
  std::uint32_t count = r.u32();
  if(count > 100000) return tl::unexpected(make_error_code(errc::count_too_large));
  std::vector<SearchResultItem> out; out.reserve(count);
  for(std::uint32_t i=0;i<count && r.ok();++i){
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
    out.push_back(std::move(item));
  }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return out;
}
tl::expected<FoundSources,std::error_code> decode_found_sources(std::span<const std::byte> data){
  ByteReader r(data);
  FoundSources fs;
  fs.hash = r.hash16();
  std::uint8_t count = r.u8();
  for(std::uint8_t i=0;i<count && r.ok();++i){
    SourceEndpoint s; s.id = r.u32(); s.port = r.u16();
    fs.sources.push_back(s);
  }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return fs;
}
}
