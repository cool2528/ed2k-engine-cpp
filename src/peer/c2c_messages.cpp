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
constexpr std::uint8_t CT_EMULECOMPAT_OPTIONS = 0xEF;
constexpr std::uint8_t CT_EMULE_MISCOPTIONS1 = 0xFA;
constexpr std::uint8_t CT_EMULE_VERSION = 0xFB;
constexpr std::uint8_t CT_EMULE_MISCOPTIONS2 = 0xFE;
constexpr std::uint32_t SO_AMULE = 3;
constexpr std::uint32_t SOURCEEXCHANGE2_VERSION = 4;

constexpr std::uint32_t emule_version_2_3_3() {
  return (SO_AMULE << 24) | (2u << 17) | (3u << 10) | (3u << 7);
}

constexpr std::uint32_t misc_options1() {
  const std::uint32_t aich = 1;
  const std::uint32_t unicode = 1;
  const std::uint32_t udp = 0;
  const std::uint32_t compression = 1;
  const std::uint32_t secure_ident = 0;
  const std::uint32_t source_exchange = 3;
  const std::uint32_t extended_requests = 0;
  const std::uint32_t comments = 1;
  const std::uint32_t multipacket = 1;
  return (aich << 29) |
         (unicode << 28) |
         (udp << 24) |
         (compression << 20) |
         (secure_ident << 16) |
         (source_exchange << 12) |
         (extended_requests << 8) |
         (comments << 4) |
         (multipacket << 1);
}

std::uint32_t misc_options2(const HelloInfo& h) {
  const std::uint32_t source_exchange2 = 1;
  const std::uint32_t ext_multipacket = 1;
  const std::uint32_t large_files = 1;
  const std::uint32_t crypt_support = h.supports_obfuscation ? 1u : 0u;
  const std::uint32_t crypt_request = h.requests_obfuscation ? 1u : 0u;
  const std::uint32_t crypt_require = h.requires_obfuscation ? 1u : 0u;
  return (source_exchange2 << 10) |
         (crypt_require << 9) |
         (crypt_request << 8) |
         (crypt_support << 7) |
         (ext_multipacket << 5) |
         (large_files << 4);
}
}
std::vector<std::byte> encode_hello(const HelloInfo& h){
  ByteWriter w;
  w.hash16(h.user_hash);
  w.u32(h.client_id);
  w.u16(h.port);
  std::vector<Tag> tags;
  tags.push_back(string_tag(tag::CT_NAME, h.nickname));
  tags.push_back(u32_tag(tag::CT_VERSION, h.version));
  tags.push_back(u32_tag(CT_EMULE_VERSION, emule_version_2_3_3()));
  tags.push_back(u32_tag(CT_EMULE_MISCOPTIONS1, misc_options1()));
  tags.push_back(u32_tag(CT_EMULE_MISCOPTIONS2, misc_options2(h)));
  tags.push_back(u32_tag(CT_EMULECOMPAT_OPTIONS, 0));
  w.u32(static_cast<std::uint32_t>(tags.size()));
  codec::write_taglist(w, tags);
  // 尾部 server_ip(4 BE)+server_port(2 LE) — aMule SendHelloTypePacket 末尾无条件写入(0/0 若未连服务器)。
  w.u32_be(h.server_ip ? h.server_ip->host() : 0);
  w.u16(h.server_port ? *h.server_port : 0);
  return w.take();
}
std::vector<std::byte> encode_hello_packet(const HelloInfo& h){
  // OP_HELLO payload = [0x10 hashsize] + body(aMule SendHelloPacket: data.WriteUInt8(16) 后 SendHelloTypePacket)。
  auto body = encode_hello(h);
  body.insert(body.begin(), std::byte{0x10});
  return body;
}
std::vector<std::byte> encode_set_req_file(const FileHash& h){ ByteWriter w; w.hash16(h); return w.take(); }
std::vector<std::byte> encode_hashset_request(const FileHash& h){ ByteWriter w; w.hash16(h); return w.take(); }
std::vector<std::byte> encode_request_filename(const FileHash& h){ ByteWriter w; w.hash16(h); return w.take(); }
tl::expected<FileHash,std::error_code> decode_file_hash_request(std::span<const std::byte> data){
  ByteReader r(data);
  FileHash h = r.hash16();
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return h;
}
std::vector<std::byte> encode_req_filename_answer(const FileHash& h, std::string_view name){
  ByteWriter w;
  w.hash16(h);
  w.u32(static_cast<std::uint32_t>(name.size()));
  w.blob(std::as_bytes(std::span{name.data(), name.size()}));
  return w.take();
}
std::vector<std::byte> encode_file_status(const FileHash& h, std::span<const bool> parts){
  ByteWriter w;
  w.hash16(h);
  w.u16(static_cast<std::uint16_t>(parts.size()));
  const std::size_t bytes_needed = (parts.size() + 7) / 8;
  for(std::size_t byte_i = 0; byte_i < bytes_needed; ++byte_i){
    std::uint8_t v = 0;
    for(std::size_t bit = 0; bit < 8; ++bit){
      const std::size_t idx = byte_i * 8 + bit;
      if(idx < parts.size() && parts[idx]) v |= static_cast<std::uint8_t>(1u << bit);
    }
    w.u8(v);
  }
  return w.take();
}
std::vector<std::byte> encode_hashset_answer(const FileHash& h, std::span<const PartHash> part_hashes){
  ByteWriter w;
  w.hash16(h);
  w.u16(static_cast<std::uint16_t>(part_hashes.size()));
  for(const auto& ph : part_hashes) w.hash16(ph);
  return w.take();
}
std::vector<std::byte> encode_start_upload(const FileHash& h){ ByteWriter w; w.hash16(h); return w.take(); }
std::vector<std::byte> encode_queue_ranking(std::uint16_t rank){
  ByteWriter w;
  w.u16(rank);
  return w.take();
}
std::vector<std::byte> encode_reask_file_ping(const FileHash& h){ ByteWriter w; w.hash16(h); return w.take(); }
std::vector<std::byte> encode_reask_ack(std::uint16_t rank){ return encode_queue_ranking(rank); }
std::vector<std::byte> encode_request_parts(const FileHash& h, std::array<std::uint32_t,3> starts, std::array<std::uint32_t,3> ends){
  ByteWriter w; w.hash16(h);
  for(auto s : starts) w.u32(s);
  for(auto e : ends) w.u32(e);
  return w.take();
}
tl::expected<RequestParts,std::error_code> decode_request_parts(std::span<const std::byte> data){
  ByteReader r(data);
  RequestParts req;
  req.hash = r.hash16();
  for(auto& s : req.starts) s = r.u32();
  for(auto& e : req.ends) e = r.u32();
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return req;
}
std::vector<std::byte> encode_sending_part(const FileHash& h, std::uint64_t start, std::span<const std::byte> data){
  ByteWriter w;
  w.hash16(h);
  w.u32(static_cast<std::uint32_t>(start));
  w.u32(static_cast<std::uint32_t>(start + data.size()));
  w.blob(data);
  return w.take();
}
std::vector<std::byte> encode_end_of_download(const FileHash& h){ ByteWriter w; w.hash16(h); return w.take(); }
std::vector<std::byte> encode_cancel_transfer(){ return {}; }

tl::expected<HelloInfo,std::error_code> decode_hello(std::span<const std::byte> data){
  // OP_HELLO payload 首字节 = 0x10 hashsize(aMule ProcessHelloPacket: ReadUInt8(); if(16!=hashsize) throw)。
  if(data.empty() || std::to_integer<std::uint8_t>(data.front()) != 0x10)
    return tl::unexpected(make_error_code(errc::unsupported_version));
  return decode_hello_answer(data.subspan(1));
}
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
    else if(t.name_id == CT_EMULE_MISCOPTIONS2 && std::holds_alternative<std::uint64_t>(t.value)){
      const auto options = std::get<std::uint64_t>(t.value);
      h.supports_obfuscation = ((options >> 7) & 0x01u) != 0;
      h.requests_obfuscation = ((options >> 8) & 0x01u) != 0;
      h.requires_obfuscation = ((options >> 9) & 0x01u) != 0;
    }
  }
  if(r.remaining() >= 6){ h.server_ip = IPv4::from_host(r.u32_be()); h.server_port = r.u16(); }
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
// aMule SendHashsetPacket (UploadClient.cpp) 线序: [file_hash:16][part_count:2 LE][part_hash:16]×count。
// 对照 aMule ProcessHashsetAnswer: 先读 file_hash 校验 == 请求 hash (不符即丢弃), 再读 count + 各 part hash。
tl::expected<std::vector<PartHash>,std::error_code> decode_hashset_answer(const FileHash& expected, std::span<const std::byte> data){
  ByteReader r(data);
  FileHash got = r.hash16();              // 前导 16 字节文件 hash
  std::uint16_t count = r.u16();
  std::vector<PartHash> out; out.reserve(count);
  for(std::uint16_t i=0;i<count && r.ok();++i) out.push_back(r.hash16());
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  if(!(got == expected)) return tl::unexpected(make_error_code(errc::hash_mismatch));
  return out;
}
tl::expected<FileNameAnswer,std::error_code> decode_req_filename_answer(std::span<const std::byte> data){
  if(data.size() < 18) return tl::unexpected(make_error_code(errc::buffer_underflow));
  ByteReader r(data);
  FileNameAnswer a;
  a.hash = r.hash16();
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));

  auto rest = data.subspan(16);
  auto byte_at = [](std::span<const std::byte> s, std::size_t i) {
    return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(s[i]));
  };

  if(rest.size() >= 4) {
    const auto len32 = byte_at(rest, 0) |
                       (byte_at(rest, 1) << 8) |
                       (byte_at(rest, 2) << 16) |
                       (byte_at(rest, 3) << 24);
    if(static_cast<std::uint64_t>(len32) <= rest.size() - 4u) {
      const auto len = static_cast<std::size_t>(len32);
      auto b = rest.subspan(4, len);
      a.name.assign(reinterpret_cast<const char*>(b.data()), len);
      return a;
    }
  }

  const auto len = static_cast<std::uint16_t>(byte_at(rest, 0) | (byte_at(rest, 1) << 8));
  if(static_cast<std::size_t>(len) > rest.size() - 2u) return tl::unexpected(make_error_code(errc::buffer_underflow));
  auto b = rest.subspan(2, len);
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

std::vector<std::byte> encode_shared_files_answer(std::span<const SharedFileEntry> files){
  ByteWriter w;
  w.u32(static_cast<std::uint32_t>(files.size()));
  for(const auto& f : files) {
    w.hash16(f.hash);
    w.u32(f.client_id);
    w.u16(f.port);
    w.u32(0); // empty tag set
  }
  return w.take();
}

tl::expected<std::vector<SharedFileEntry>, std::error_code>
decode_shared_files_answer(std::span<const std::byte> data){
  ByteReader r(data);
  const auto count = r.u32();
  if(count > 1000000) return tl::unexpected(make_error_code(errc::count_too_large));
  std::vector<SharedFileEntry> out;
  out.reserve(count);
  for(std::uint32_t i = 0; i < count; ++i) {
    SharedFileEntry e;
    e.hash = r.hash16();
    e.client_id = r.u32();
    e.port = r.u16();
    const auto tags = r.u32();
    if(tags != 0) return tl::unexpected(make_error_code(errc::unsupported_version));
    if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
    out.push_back(e);
  }
  return out;
}

std::vector<std::byte> encode_request_sources2(const FileHash& h){ ByteWriter w; w.hash16(h); return w.take(); }

std::vector<std::byte> encode_multipacket_request_sources2(const FileHash& h, std::uint8_t version, std::uint16_t options){
  ByteWriter w;
  w.hash16(h);
  w.u8(op::REQUESTSOURCES2);
  w.u8(version);
  w.u16(options);
  return w.take();
}

tl::expected<FileHash, std::error_code> decode_request_sources2(std::span<const std::byte> data){
  if(data.size() == 16) return decode_file_hash_request(data);
  if(data.size() != 19) return tl::unexpected(make_error_code(errc::buffer_underflow));
  ByteReader r(data);
  (void)r.u8();
  (void)r.u16();
  FileHash h = r.hash16();
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return h;
}

std::vector<std::byte> encode_answer_sources2(const FileHash& h, std::span<const PeerSource> sources, std::uint8_t version){
  ByteWriter w;
  w.u8(version);
  w.hash16(h);
  w.u16(static_cast<std::uint16_t>(sources.size()));
  for(const auto& s : sources) {
    w.u32(s.client_id);
    w.u16(s.port);
    w.u32(s.server_ip);
    w.u16(s.server_port);
    w.hash16(s.user_hash);
    w.u8(s.crypt_options);
  }
  return w.take();
}

tl::expected<SourceExchangeAnswer, std::error_code> decode_answer_sources2(std::span<const std::byte> data){
  ByteReader r(data);
  SourceExchangeAnswer out;
  out.version = r.u8();
  out.hash = r.hash16();
  const auto count = r.u16();
  out.sources.reserve(count);
  for(std::uint16_t i = 0; i < count && r.ok(); ++i) {
    PeerSource s;
    s.client_id = r.u32();
    s.port = r.u16();
    s.server_ip = r.u32();
    s.server_port = r.u16();
    s.user_hash = r.hash16();
    s.crypt_options = r.u8();
    out.sources.push_back(s);
  }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return out;
}

std::vector<std::byte> encode_file_desc(std::uint8_t rating, std::string_view comment){
  ByteWriter w;
  w.u8(rating);
  w.u32(static_cast<std::uint32_t>(comment.size()));
  w.blob(std::as_bytes(std::span{comment.data(), comment.size()}));
  return w.take();
}

tl::expected<FileDesc, std::error_code> decode_file_desc(std::span<const std::byte> data){
  ByteReader r(data);
  FileDesc out;
  out.rating = r.u8();
  const auto len = r.u32();
  auto blob = r.blob(len);
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  if(out.rating > 5) out.rating = 0;
  out.comment.assign(reinterpret_cast<const char*>(blob.data()), blob.size());
  return out;
}

std::vector<std::byte> encode_preview_request(const FileHash& h){
  ByteWriter w;
  w.hash16(h);
  return w.take();
}

std::vector<std::byte> encode_preview_answer(const FileHash& h, std::span<const std::span<const std::byte>> frames){
  ByteWriter w;
  w.hash16(h);
  w.u8(static_cast<std::uint8_t>(frames.size()));
  for(auto frame : frames) {
    w.u32(static_cast<std::uint32_t>(frame.size()));
    w.blob(frame);
  }
  return w.take();
}

tl::expected<PreviewAnswer, std::error_code> decode_preview_answer(std::span<const std::byte> data){
  ByteReader r(data);
  PreviewAnswer out;
  out.hash = r.hash16();
  const auto count = r.u8();
  out.frames.reserve(count);
  for(std::uint8_t i = 0; i < count && r.ok(); ++i) {
    const auto size = r.u32();
    auto frame = r.blob(size);
    out.frames.emplace_back(frame.begin(), frame.end());
  }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return out;
}

std::vector<std::byte> encode_chat_message(std::string_view text){
  ByteWriter w;
  w.string16(text);
  return w.take();
}

tl::expected<std::string, std::error_code> decode_chat_message(std::span<const std::byte> data){
  ByteReader r(data);
  auto text = r.string16();
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return text;
}

std::vector<std::byte> encode_aich_file_hash_req(const FileHash& h){
  ByteWriter w;
  w.hash16(h);
  return w.take();                       // file_hash(16) — aMule CPacket(OP_AICHFILEHASHREQ,16,OP_EMULEPROT)
}
std::vector<std::byte> encode_aich_file_hash_ans(const FileHash& h, const AICHHash& master){
  ByteWriter w;
  w.hash16(h);
  w.hash20(master.bytes());
  return w.take();
}
tl::expected<AICHHash,std::error_code> decode_aich_file_hash_ans(std::span<const std::byte> data){
  ByteReader r(data);
  r.hash16();                            // file_hash(16) — 调用方已知请求的文件,此处丢弃
  auto master = r.hash20();              // aich_master_hash(20)
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return AICHHash::from_bytes(master);
}
std::vector<std::byte> encode_aich_answer(const FileHash& h, const AICHHash& master, std::uint16_t part_index,
                                          std::span<const AICHProofHash> proof){
  ByteWriter w;
  w.hash16(h);
  w.u16(part_index);
  w.hash20(master.bytes());
  std::uint16_t count16 = 0, count32 = 0;
  for(const auto& p : proof) {
    if(p.identifier <= 0xFFFFu) ++count16;
    else ++count32;
  }
  w.u16(count16);
  for(const auto& p : proof){
    if(p.identifier > 0xFFFFu) continue;
    w.u16(static_cast<std::uint16_t>(p.identifier));
    w.hash20(p.hash);
  }
  w.u16(count32);
  for(const auto& p : proof){
    if(p.identifier <= 0xFFFFu) continue;
    w.u32(p.identifier);
    w.hash20(p.hash);
  }
  return w.take();
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
