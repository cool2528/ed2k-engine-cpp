#include "ed2k/server/messages.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/codec/tag.hpp"        // Tag, write_taglist
namespace ed2k::server {
using codec::ByteWriter;
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
}
