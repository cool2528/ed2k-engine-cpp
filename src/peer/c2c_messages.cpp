#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/codec/tag.hpp"
namespace ed2k::peer {
namespace tag = ed2k::server::tag;   // CT_NAME/CT_VERSION 复用 server 的 tag-ID
using codec::ByteWriter;
using codec::Tag;
namespace {
Tag string_tag(std::uint8_t id, std::string_view v){ Tag t; t.name_id=id; t.value=std::string(v); return t; }
Tag u32_tag(std::uint8_t id, std::uint32_t v){ Tag t; t.name_id=id; t.value=std::uint64_t(v); return t; }
}
std::vector<std::byte> encode_hello(const HelloInfo& h){
  ByteWriter w;
  w.hash16(h.user_hash);
  w.u32(h.client_id);
  w.u16(h.port);
  std::vector<Tag> tags;
  tags.push_back(string_tag(tag::CT_NAME, h.nickname));
  tags.push_back(u32_tag(tag::CT_VERSION, h.version));
  w.u32(static_cast<std::uint32_t>(tags.size()));
  codec::write_taglist(w, tags);
  return w.take();
}
std::vector<std::byte> encode_set_req_file(const FileHash& h){ ByteWriter w; w.hash16(h); return w.take(); }
std::vector<std::byte> encode_hashset_request(const FileHash& h){ ByteWriter w; w.hash16(h); return w.take(); }
std::vector<std::byte> encode_request_filename(const FileHash& h){ ByteWriter w; w.hash16(h); return w.take(); }
std::vector<std::byte> encode_start_upload(const FileHash& h){ ByteWriter w; w.hash16(h); return w.take(); }
std::vector<std::byte> encode_request_parts(const FileHash& h, std::array<std::uint32_t,3> starts, std::array<std::uint32_t,3> ends){
  ByteWriter w; w.hash16(h);
  for(auto s : starts) w.u32(s);
  for(auto e : ends) w.u32(e);
  return w.take();
}
std::vector<std::byte> encode_end_of_download(const FileHash& h){ ByteWriter w; w.hash16(h); return w.take(); }
std::vector<std::byte> encode_cancel_transfer(){ return {}; }
}
