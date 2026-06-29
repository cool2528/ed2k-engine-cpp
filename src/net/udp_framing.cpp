#include "ed2k/net/udp_framing.hpp"
#include "net/inflate.hpp"          // P2 zlib_inflate（私有头，经 src PRIVATE include）
#include "ed2k/util/error.hpp"
namespace ed2k::net {
std::vector<std::byte> encode_udp_packet(const Packet& p){
  std::vector<std::byte> out;
  out.push_back(std::byte(p.protocol));
  out.push_back(std::byte(p.opcode));
  out.insert(out.end(), p.payload.begin(), p.payload.end());
  return out;
}
tl::expected<Packet,std::error_code> parse_udp_datagram(std::span<const std::byte> data){
  if(data.size() < 2) return tl::unexpected(make_error_code(errc::buffer_underflow));
  Packet p;
  p.protocol = std::to_integer<std::uint8_t>(data[0]);
  p.opcode   = std::to_integer<std::uint8_t>(data[1]);
  auto rest = data.subspan(2);
  if(p.protocol == proto::zlib){
    auto dec = zlib_inflate(rest, MAX_PACKET_SIZE);
    if(!dec) return tl::unexpected(dec.error());
    p.protocol = proto::eMule;             // 归一化
    p.payload = std::move(*dec);
    return p;
  }
  p.payload.assign(rest.begin(), rest.end());
  return p;
}
}
