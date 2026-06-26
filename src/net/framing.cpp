#include "ed2k/net/framing.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"
#include "net/inflate.hpp"
namespace ed2k::net {
std::vector<std::byte> encode_frame(const Packet& p){
  codec::ByteWriter w;
  w.u8(p.protocol);
  w.u32(static_cast<std::uint32_t>(1 + p.payload.size()));   // size 含 opcode
  w.u8(p.opcode);
  w.blob(p.payload);
  return w.take();
}
tl::expected<FrameHeader,std::error_code> parse_header(std::span<const std::byte,5> hdr){
  codec::ByteReader r(hdr);
  FrameHeader h{};
  h.protocol = r.u8();
  h.size = r.u32();
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  if(h.size == 0) return tl::unexpected(make_error_code(errc::buffer_underflow));
  if(h.size > MAX_PACKET_SIZE) return tl::unexpected(make_error_code(errc::packet_too_large));
  return h;
}
tl::expected<Packet,std::error_code> assemble(std::uint8_t protocol, std::span<const std::byte> body){
  if(body.empty()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  Packet p;
  p.opcode = std::to_integer<std::uint8_t>(body[0]);
  auto rest = body.subspan(1);
  if(protocol == proto::zlib){
    auto dec = zlib_inflate(rest, MAX_PACKET_SIZE);
    if(!dec) return tl::unexpected(dec.error());
    p.protocol = proto::eMule;                 // 归一化
    p.payload = std::move(*dec);
    return p;
  }
  p.protocol = protocol;
  p.payload.assign(rest.begin(), rest.end());
  return p;
}
}
