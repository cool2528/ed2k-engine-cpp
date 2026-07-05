#include "ed2k/metfile/server_met.hpp"
#include "ed2k/codec/byte_io.hpp"
#include <unordered_set>
namespace ed2k {
using namespace ed2k::codec;
namespace {
void write_u32_tag(ByteWriter& w, std::uint8_t id, std::uint32_t value){
  w.u8(tagtype::Uint32 | tagtype::NameFlag);
  w.u8(id);
  w.u32(value);
}
void write_u16_tag(ByteWriter& w, std::uint8_t id, std::uint16_t value){
  w.u8(tagtype::Uint16 | tagtype::NameFlag);
  w.u8(id);
  w.u16(value);
}
bool numeric_tag(const Tag& t){
  return std::holds_alternative<std::uint64_t>(t.value);
}
std::uint32_t numeric32(const Tag& t){
  return static_cast<std::uint32_t>(std::get<std::uint64_t>(t.value));
}
std::uint16_t numeric16(const Tag& t){
  return static_cast<std::uint16_t>(std::get<std::uint64_t>(t.value));
}
}
tl::expected<ServerList,std::error_code> parse_server_met(std::span<const std::byte> data){
  ByteReader r(data);
  std::uint8_t magic=r.u8();
  if(magic!=0x0E && magic!=0xE0) return tl::unexpected(make_error_code(errc::bad_magic));
  std::uint32_t count=r.u32();
  if(count>1000000) return tl::unexpected(make_error_code(errc::count_too_large));
  ServerList list; list.servers.reserve(count);
  for(std::uint32_t i=0;i<count;++i){
    ServerEntry e; e.ip=IPv4::from_host(r.u32_be()); e.port=r.u16();
    std::uint32_t tagc=r.u32();
    auto tags=read_taglist(r,tagc); if(!tags) return tl::unexpected(tags.error());
    for(auto& t:*tags){
      if(t.name_id==stag::Name && std::holds_alternative<std::string>(t.value)) e.name=std::get<std::string>(t.value);
      else if(t.name_id==stag::Description && std::holds_alternative<std::string>(t.value)) e.description=std::get<std::string>(t.value);
      else if(t.name_id==stag::MaxUsers && std::holds_alternative<std::uint64_t>(t.value)) e.max_users=std::uint32_t(std::get<std::uint64_t>(t.value));
      else if(t.name_id==stag::UdpFlags && numeric_tag(t)) e.udp_flags=numeric32(t);
      else if(t.name_id==stag::UdpKey && numeric_tag(t)) e.udp_key=numeric32(t);
      else if(t.name_id==stag::UdpKeyIp && numeric_tag(t)) e.udp_key_ip=numeric32(t);
      else if(t.name_id==stag::TcpPortObfuscation && numeric_tag(t)) e.tcp_obf_port=numeric16(t);
      else if(t.name_id==stag::UdpPortObfuscation && numeric_tag(t)) e.udp_obf_port=numeric16(t);
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
    w.u32_be(e.ip.host()); w.u16(e.port);
    std::vector<codec::Tag> tags;
    if(!e.name.empty()){ codec::Tag t; t.name_id=stag::Name; t.value=e.name; tags.push_back(t); }
    if(!e.description.empty()){ codec::Tag t; t.name_id=stag::Description; t.value=e.description; tags.push_back(t); }
    if(e.max_users){ codec::Tag t; t.name_id=stag::MaxUsers; t.value=std::uint64_t(e.max_users); tags.push_back(t); }
    std::uint32_t tag_count = std::uint32_t(tags.size() + e.extra.size());
    if(e.udp_flags) ++tag_count;
    if(e.udp_key) ++tag_count;
    if(e.udp_key_ip) ++tag_count;
    if(e.tcp_obf_port) ++tag_count;
    if(e.udp_obf_port) ++tag_count;
    w.u32(tag_count);
    write_taglist(w, tags);
    if(e.udp_flags) write_u32_tag(w, stag::UdpFlags, e.udp_flags);
    if(e.udp_key) write_u32_tag(w, stag::UdpKey, e.udp_key);
    if(e.udp_key_ip) write_u32_tag(w, stag::UdpKeyIp, e.udp_key_ip);
    if(e.tcp_obf_port) write_u16_tag(w, stag::TcpPortObfuscation, e.tcp_obf_port);
    if(e.udp_obf_port) write_u16_tag(w, stag::UdpPortObfuscation, e.udp_obf_port);
    write_taglist(w, e.extra);
  }
  return w.take();
}

ServerList merge_server_list(ServerList existing,
                             std::span<const std::pair<IPv4, std::uint16_t>> fetched){
  std::unordered_set<std::uint64_t> seen;
  seen.reserve(existing.servers.size() + fetched.size());
  auto key=[](IPv4 ip, std::uint16_t port){
    return (std::uint64_t(ip.host()) << 16) | port;
  };
  for(const auto& server : existing.servers) seen.insert(key(server.ip, server.port));
  for(const auto& [ip, port] : fetched){
    if(!seen.insert(key(ip, port)).second) continue;
    ServerEntry entry;
    entry.ip = ip;
    entry.port = port;
    existing.servers.push_back(std::move(entry));
  }
  return existing;
}
}
