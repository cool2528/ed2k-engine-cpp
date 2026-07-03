#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/codec/tag.hpp"
#include "ed2k/net/packet.hpp"   // net::MAX_PACKET_SIZE
#include "net/inflate.hpp"       // P2 net::zlib_inflate（私有头，经 src PRIVATE include）
namespace ed2k::peer {
namespace tag = ed2k::server::tag;   // CT_NAME/CT_VERSION 复用 server 的 tag-ID
using codec::ByteWriter;
using codec::ByteReader;
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

tl::expected<HelloInfo,std::error_code> decode_hello_answer(std::span<const std::byte> data){
  ByteReader r(data);
  HelloInfo h;
  h.user_hash = r.hash16();
  h.client_id = r.u32();
  h.port = r.u16();
  std::uint32_t tc = r.u32();
  auto tags = codec::read_taglist(r, tc);
  if(!tags) return tl::unexpected(tags.error());
  for(auto& t : *tags){
    if(t.name_id == tag::CT_NAME && std::holds_alternative<std::string>(t.value)) h.nickname = std::get<std::string>(t.value);
    else if(t.name_id == tag::CT_VERSION && std::holds_alternative<std::uint64_t>(t.value)) h.version = static_cast<std::uint32_t>(std::get<std::uint64_t>(t.value));
  }
  if(r.remaining() >= 6){ h.server_ip = IPv4{r.u32_be()}; h.server_port = r.u16(); }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return h;
}
tl::expected<FileStatus,std::error_code> decode_file_status(std::span<const std::byte> data){
  ByteReader r(data);
  FileStatus fs; fs.hash = r.hash16();
  std::uint16_t count = r.u16();
  std::size_t bytes_needed = (static_cast<std::size_t>(count) + 7) / 8;
  auto bitspan = r.blob(bytes_needed);
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  fs.parts.resize(count, false);
  for(std::uint16_t i=0;i<count && i/8 < bitspan.size();++i){
    std::uint8_t b = std::to_integer<std::uint8_t>(bitspan[i/8]);
    fs.parts[i] = ((b >> (i%8)) & 1u) != 0;
  }
  return fs;
}
tl::expected<std::vector<PartHash>,std::error_code> decode_hashset_answer(std::span<const std::byte> data){
  ByteReader r(data);
  std::uint16_t count = r.u16();
  std::vector<PartHash> out; out.reserve(count);
  for(std::uint16_t i=0;i<count && r.ok();++i) out.push_back(r.hash16());
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return out;
}
tl::expected<FileNameAnswer,std::error_code> decode_req_filename_answer(std::span<const std::byte> data){
  ByteReader r(data);
  FileNameAnswer a; a.hash = r.hash16();
  std::uint32_t len = r.u32();
  auto b = r.blob(len);
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  a.name.assign(reinterpret_cast<const char*>(b.data()), len);
  return a;
}
tl::expected<std::uint16_t,std::error_code> decode_queue_ranking(std::span<const std::byte> data){
  ByteReader r(data);
  std::uint16_t rank = r.u16();
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return rank;
}
tl::expected<Block,std::error_code> decode_sending_part(std::span<const std::byte> data){
  ByteReader r(data);
  Block b; b.hash = r.hash16(); b.start = r.u32(); b.end = r.u32();
  std::size_t dlen = data.size() - r.pos();
  auto blob = r.blob(dlen);
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  b.data.assign(blob.begin(), blob.end());
  return b;
}
tl::expected<Block,std::error_code> decode_compressed_part(std::span<const std::byte> data){
  ByteReader r(data);
  Block b; b.hash = r.hash16(); b.start = r.u32(); b.end = r.u32();
  std::size_t clen = data.size() - r.pos();
  auto comp = r.blob(clen);
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  auto dec = ed2k::net::zlib_inflate(comp, ed2k::net::MAX_PACKET_SIZE);
  if(!dec) return tl::unexpected(dec.error());
  b.data = std::move(*dec);
  return b;
}
tl::expected<FileHash,std::error_code> decode_file_req_ans_no_fil(std::span<const std::byte> data){
  ByteReader r(data);
  FileHash h = r.hash16();
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return h;
}

std::vector<std::byte> encode_aich_file_hash_req(const FileHash& h){
  ByteWriter w;
  w.hash16(h);
  return w.take();                       // file_hash(16) — aMule CPacket(OP_AICHFILEHASHREQ,16,OP_EMULEPROT)
}
tl::expected<AICHHash,std::error_code> decode_aich_file_hash_ans(std::span<const std::byte> data){
  ByteReader r(data);
  r.hash16();                            // file_hash(16) — 调用方已知请求的文件,此处丢弃
  auto master = r.hash20();              // aich_master_hash(20)
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return AICHHash::from_bytes(master);
}

std::vector<std::byte> encode_aich_request(const FileHash& h, const AICHHash& master, std::uint16_t part_index){
  // aMule SendAICHRequest 顺序: file_hash(16) -> part_index(u16) -> master_hash(20) = 38B
  ByteWriter w;
  w.hash16(h);
  w.u16(part_index);
  w.hash20(master.bytes());
  return w.take();
}
tl::expected<AICHRecoveryData,std::error_code> decode_aich_answer(std::span<const std::byte> data){
  ByteReader r(data);
  r.hash16();                            // file_hash(16)
  r.u16();                               // part_index(u16) — 回显请求的 part,校验由 C2CConnection 负责
  r.hash20();                            // master_hash(20) — 校验由 C2CConnection 负责
  // V2 recovery data (aMule ReadRecoveryData)
  std::uint16_t count16 = r.u16();       // 16-bit 标识符 hash 数
  AICHRecoveryData out;
  out.hashes.reserve(128);               // 单 part 全 hashset ≤ ~113 节点; 避免 untrusted count 驱动分配
  for(std::uint16_t i=0;i<count16 && r.ok();++i){
    AICHProofHash p; p.identifier = r.u16(); p.hash = r.hash20();
    out.hashes.push_back(std::move(p));
  }
  std::uint16_t count32 = r.u16();       // 32-bit 标识符 hash 数(大文件路径;非大文件为 0)
  for(std::uint16_t i=0;i<count32 && r.ok();++i){
    AICHProofHash p; p.identifier = r.u32(); p.hash = r.hash20();
    out.hashes.push_back(std::move(p));
  }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return out;
}

std::vector<std::byte> encode_request_parts_i64(const FileHash& h, std::array<std::uint64_t, 3> starts, std::array<std::uint64_t, 3> ends){
  ByteWriter w;
  w.hash16(h);
  for(auto s : starts) w.u64(s);
  for(auto e : ends) w.u64(e);
  return w.take();
}
tl::expected<Block,std::error_code> decode_sending_part_i64(std::span<const std::byte> data){
  ByteReader r(data);
  Block b; b.hash = r.hash16(); b.start = r.u64(); b.end = r.u64();
  std::size_t dlen = data.size() - r.pos();
  auto blob = r.blob(dlen);
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  b.data.assign(blob.begin(), blob.end());
  return b;
}
tl::expected<Block,std::error_code> decode_compressed_part_i64(std::span<const std::byte> data){
  ByteReader r(data);
  Block b; b.hash = r.hash16(); b.start = r.u64(); b.end = r.u64();
  std::size_t clen = data.size() - r.pos();
  auto comp = r.blob(clen);
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  auto dec = ed2k::net::zlib_inflate(comp, ed2k::net::MAX_PACKET_SIZE);
  if(!dec) return tl::unexpected(dec.error());
  b.data = std::move(*dec);
  return b;
}
}
