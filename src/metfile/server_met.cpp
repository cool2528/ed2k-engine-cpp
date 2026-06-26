#include "ed2k/metfile/server_met.hpp"
#include "ed2k/codec/byte_io.hpp"
namespace ed2k {
using namespace ed2k::codec;
tl::expected<ServerList,std::error_code> parse_server_met(std::span<const std::byte> data){
  ByteReader r(data);
  std::uint8_t magic=r.u8();
  if(magic!=0x0E && magic!=0xE0) return tl::unexpected(make_error_code(errc::bad_magic));
  std::uint32_t count=r.u32();
  if(count>1000000) return tl::unexpected(make_error_code(errc::count_too_large));
  ServerList list; list.servers.reserve(count);
  for(std::uint32_t i=0;i<count;++i){
    ServerEntry e; e.ip=IPv4{r.u32()}; e.port=r.u16();
    std::uint32_t tagc=r.u32();
    auto tags=read_taglist(r,tagc); if(!tags) return tl::unexpected(tags.error());
    for(auto& t:*tags){
      if(t.name_id==stag::Name && std::holds_alternative<std::string>(t.value)) e.name=std::get<std::string>(t.value);
      else if(t.name_id==stag::Description && std::holds_alternative<std::string>(t.value)) e.description=std::get<std::string>(t.value);
      else if(t.name_id==stag::MaxUsers && std::holds_alternative<std::uint64_t>(t.value)) e.max_users=std::uint32_t(std::get<std::uint64_t>(t.value));
      else e.extra.push_back(std::move(t));
    }
    if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
    list.servers.push_back(std::move(e));
  }
  return list;
}
std::vector<std::byte> write_server_met(const ServerList& list){
  ByteWriter w; w.u8(0xE0); w.u32(std::uint32_t(list.servers.size()));
  for(auto& e:list.servers){
    w.u32(e.ip.value); w.u16(e.port);
    std::vector<codec::Tag> tags;
    if(!e.name.empty()){ codec::Tag t; t.name_id=stag::Name; t.value=e.name; tags.push_back(t); }
    if(!e.description.empty()){ codec::Tag t; t.name_id=stag::Description; t.value=e.description; tags.push_back(t); }
    if(e.max_users){ codec::Tag t; t.name_id=stag::MaxUsers; t.value=std::uint64_t(e.max_users); tags.push_back(t); }
    for(auto& t:e.extra) tags.push_back(t);
    w.u32(std::uint32_t(tags.size()));
    write_taglist(w, tags);
  }
  return w.take();
}
}
