#include <gtest/gtest.h>
#include <array>
#include <optional>
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/codec/tag.hpp"
#include "crypto/sha1.hpp"
#include "ed2k/peer/c2c_messages.hpp"
using namespace ed2k; using namespace ed2k::peer; using namespace ed2k::server;
using ed2k::codec::ByteWriter;

static std::vector<std::byte> bytes(std::initializer_list<int> xs){
  std::vector<std::byte> v;
  for(int x: xs) v.push_back(std::byte(x));
  return v;
}
static std::vector<std::byte> hex(std::string_view h){
  std::vector<std::byte> v;
  auto val=[&](char c)->int{ return c<='9'? c-'0' : (c|0x20)-'a'+10; };
  for(std::size_t i=0;i+1<h.size();i+=2)
    v.push_back(std::byte(val(h[i])*16+val(h[i+1])));
  return v;
}
static std::array<std::byte, 20> sha1_from_hex(std::string_view h){
  std::array<std::byte, 20> out{};
  auto val=[&](char c)->int{ return c<='9'? c-'0' : (c|0x20)-'a'+10; };
  for(std::size_t b=0;b<20 && 2*b+1<h.size();++b){
    out[b] = std::byte(val(h[2*b])*16 + val(h[2*b+1]));
  }
  return out;
}

TEST(C2CMessages, EncodeHello){
  HelloInfo h;
  h.user_hash=*UserHash::from_hex("0123456789abcdeffedcba9876543210");
  h.client_id=0x01020304u;
  h.port=0x1234u;
  h.nickname="u";
  h.version=0x3C;
  auto out=encode_hello(h);
  std::vector<std::byte> want;
  auto app=[&](const std::vector<std::byte>& b){ want.insert(want.end(), b.begin(), b.end()); };
  app(hex("0123456789abcdeffedcba9876543210"));
  app(bytes({0x04,0x03,0x02,0x01}));
  app(bytes({0x34,0x12}));
  app(bytes({6,0,0,0}));
  app(bytes({0x82,tag::CT_NAME, 0x01,0x00,'u'}));
  app(bytes({0x83,tag::CT_VERSION, 0x3c,0x00,0x00,0x00}));
  app(bytes({0x83,0xFB, 0x80,0x0D,0x04,0x03})); // CT_EMULE_VERSION: aMule 2.3.3 compatible id.
  app(bytes({0x83,0xFA, 0x12,0x30,0x10,0x30})); // CT_EMULE_MISCOPTIONS1: SX1 v3 + comments + multipacket + AICH.
  app(bytes({0x83,0xFE, 0x30,0x04,0x00,0x00})); // CT_EMULE_MISCOPTIONS2: SX2 + ext multipacket + large files.
  app(bytes({0x83,0xEF, 0x00,0x00,0x00,0x00})); // CT_EMULECOMPAT_OPTIONS.
  // 尾部 server_ip(4 BE)+server_port(2 LE),未连服务器为 0(aMule SendHelloTypePacket 末尾无条件写入)。
  app(bytes({0,0,0,0, 0,0}));
  EXPECT_EQ(out, want);
}
TEST(C2CMessages, EncodeHelloAdvertisesEmuleSourceExchange2){
  HelloInfo h;
  h.user_hash=*UserHash::from_hex("0123456789abcdeffedcba9876543210");
  h.client_id=0x01020304u;
  h.port=0x1234u;
  h.nickname="u";
  h.version=0x3C;
  auto out=encode_hello(h);

  ed2k::codec::ByteReader r(out);
  (void)r.hash16();
  (void)r.u32();
  (void)r.u16();
  const auto tag_count = r.u32();
  auto tags = ed2k::codec::read_taglist(r, tag_count);
  ASSERT_TRUE(tags.has_value());

  std::optional<std::uint64_t> misc1;
  std::optional<std::uint64_t> misc2;
  for(const auto& tag : *tags) {
    if(!std::holds_alternative<std::uint64_t>(tag.value)) continue;
    if(tag.name_id == 0xFA) misc1 = std::get<std::uint64_t>(tag.value);
    if(tag.name_id == 0xFE) misc2 = std::get<std::uint64_t>(tag.value);
  }

  ASSERT_TRUE(misc1.has_value());
  ASSERT_TRUE(misc2.has_value());
  EXPECT_EQ((*misc1 >> 12) & 0x0Fu, 3u);  // SourceExchange v1 version.
  EXPECT_EQ((*misc1 >> 8) & 0x0Fu, 0u);   // No extended request payloads in multipacket.
  EXPECT_EQ((*misc1 >> 4) & 0x0Fu, 1u);   // Comments v1.
  EXPECT_EQ((*misc1 >> 1) & 0x01u, 1u);   // Multipacket.
  EXPECT_EQ((*misc2 >> 10) & 0x01u, 1u);  // SourceExchange2 supported.
  EXPECT_EQ((*misc2 >> 5) & 0x01u, 1u);   // Extended multipacket.
  EXPECT_EQ((*misc2 >> 4) & 0x01u, 1u);   // Large files.
}
TEST(C2CMessages, EncodeHelloPacket){
  // OP_HELLO payload = [0x10 hashsize] + encode_hello body(aMule SendHelloPacket: WriteUInt8(16) 后 SendHelloTypePacket)。
  HelloInfo h;
  h.user_hash=*UserHash::from_hex("0123456789abcdeffedcba9876543210");
  h.client_id=0x01020304u;
  h.port=0x1234u;
  h.nickname="u";
  h.version=0x3C;
  auto body=encode_hello(h);
  auto out=encode_hello_packet(h);
  ASSERT_GE(out.size(), 1u);
  EXPECT_EQ(std::to_integer<int>(out[0]), 0x10);
  EXPECT_EQ(std::vector<std::byte>(out.begin()+1, out.end()), body);
}
TEST(C2CMessages, EncodeSetReqFile){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  EXPECT_EQ(encode_set_req_file(h), hex("00112233445566778899aabbccddeeff"));
}
TEST(C2CMessages, EncodeHashsetRequest){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  EXPECT_EQ(encode_hashset_request(h), hex("00112233445566778899aabbccddeeff"));
}
TEST(C2CMessages, EncodeRequestFilename){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  EXPECT_EQ(encode_request_filename(h), hex("00112233445566778899aabbccddeeff"));
}
TEST(C2CMessages, DecodeFileHashRequest){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  auto out=decode_file_hash_request(hex("00112233445566778899aabbccddeeff"));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, h);
  EXPECT_FALSE(decode_file_hash_request(bytes({1,2,3})).has_value());
}
TEST(C2CMessages, EncodeReqFilenameAnswerForUpload){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  auto out=encode_req_filename_answer(h, "file.bin");
  ByteWriter w;
  w.hash16(h);
  w.u32(8);
  w.blob(bytes({'f','i','l','e','.','b','i','n'}));
  EXPECT_EQ(out, w.take());
}
TEST(C2CMessages, EncodeFileStatusCompleteFileAsCountZero){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  auto out=encode_file_status(h, {});
  ByteWriter w;
  w.hash16(h);
  w.u16(0);
  EXPECT_EQ(out, w.take());
}
TEST(C2CMessages, EncodeHashsetAnswerIncludesFileHashPrefix){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  std::array parts{
    *PartHash::from_hex("11111111111111111111111111111111"),
    *PartHash::from_hex("22222222222222222222222222222222")
  };
  auto out=encode_hashset_answer(h, parts);
  ByteWriter w;
  w.hash16(h);
  w.u16(2);
  w.hash16(parts[0]);
  w.hash16(parts[1]);
  EXPECT_EQ(out, w.take());
}
TEST(C2CMessages, EncodeStartUpload){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  EXPECT_EQ(encode_start_upload(h), hex("00112233445566778899aabbccddeeff"));
}
TEST(C2CMessages, EncodeQueueRanking){
  auto out=encode_queue_ranking(42);
  EXPECT_EQ(out, bytes({42,0}));
}
TEST(C2CMessages, EncodeUdpReaskFilePing){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  EXPECT_EQ(encode_reask_file_ping(h), hex("00112233445566778899aabbccddeeff"));
}
TEST(C2CMessages, EncodeUdpReaskAck){
  auto out=encode_reask_ack(42);
  EXPECT_EQ(out, bytes({42,0}));
}
TEST(C2CMessages, EncodeSharedFilesAnswer){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  SharedFileEntry entry{h, 0x0100007Fu, 4662};
  auto out=encode_shared_files_answer(std::array{entry});
  ByteWriter w;
  w.u32(1);
  w.hash16(h);
  w.u32(0x0100007Fu);
  w.u16(4662);
  w.u32(0);
  EXPECT_EQ(out, w.take());
}
TEST(C2CMessages, EncodeRequestSources2){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  EXPECT_EQ(encode_request_sources2(h), hex("00112233445566778899aabbccddeeff"));
}
TEST(C2CMessages, DecodeRequestSources2){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  auto out=decode_request_sources2(hex("00112233445566778899aabbccddeeff"));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, h);
  EXPECT_FALSE(decode_request_sources2(bytes({4,0,0,1,2,3})).has_value());
}
TEST(C2CMessages, DecodeRequestSources2WithVersionOptions){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  auto out=decode_request_sources2(hex("04000000112233445566778899aabbccddeeff"));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, h);
}
TEST(C2CMessages, EncodeAndDecodeAnswerSources2){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  PeerSource src{0x0100007Fu, 4662, 0, 0, *UserHash::from_hex("11111111111111111111111111111111"), 0};
  auto out=encode_answer_sources2(h, std::array{src});
  ByteWriter w;
  w.u8(4);
  w.hash16(h);
  w.u16(1);
  w.u32(0x0100007Fu);
  w.u16(4662);
  w.u32(0);
  w.u16(0);
  w.hash16(src.user_hash);
  w.u8(0);
  EXPECT_EQ(out, w.take());
  auto decoded=decode_answer_sources2(out);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->hash, h);
  ASSERT_EQ(decoded->sources.size(), 1u);
  EXPECT_EQ(decoded->sources[0].client_id, 0x0100007Fu);
  EXPECT_EQ(decoded->sources[0].port, 4662u);
  EXPECT_EQ(decoded->sources[0].user_hash, src.user_hash);
}
TEST(C2CMessages, EncodeAndDecodeFileDesc){
  auto out=encode_file_desc(5, "verified");
  EXPECT_EQ(out, bytes({5,8,0,0,0,'v','e','r','i','f','i','e','d'}));
  auto decoded=decode_file_desc(out);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->rating, 5u);
  EXPECT_EQ(decoded->comment, "verified");
}
TEST(C2CMessages, EncodeRequestParts){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  auto out=encode_request_parts(h, {100,200,300}, {150,250,350});
  std::vector<std::byte> want=hex("00112233445566778899aabbccddeeff");
  for(int s : {100,200,300}) {
    auto b=bytes({s&0xff,(s>>8)&0xff,0,0});
    want.insert(want.end(), b.begin(), b.end());
  }
  for(int e : {150,250,350}) {
    auto b=bytes({e&0xff,(e>>8)&0xff,0,0});
    want.insert(want.end(), b.begin(), b.end());
  }
  EXPECT_EQ(out, want);
}
TEST(C2CMessages, DecodeRequestParts){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  auto out=decode_request_parts(encode_request_parts(h, {100,200,300}, {150,250,350}));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->hash, h);
  EXPECT_EQ(out->starts, (std::array<std::uint64_t,3>{100,200,300}));
  EXPECT_EQ(out->ends, (std::array<std::uint64_t,3>{150,250,350}));
}
TEST(C2CMessages, EncodeSendingPart){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  auto data=bytes({1,2,3});
  auto out=encode_sending_part(h, 100, data);
  ByteWriter w;
  w.hash16(h);
  w.u32(100);
  w.u32(103);
  w.blob(data);
  EXPECT_EQ(out, w.take());
}
TEST(C2CMessages, EncodeAichFileHashAns){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  AICHHash master = AICHHash::from_bytes(sha1_from_hex("00112233445566778899aabbccddeeff00112233"));
  auto out=encode_aich_file_hash_ans(h, master);
  ByteWriter w;
  w.hash16(h);
  w.hash20(master.bytes());
  EXPECT_EQ(out, w.take());
}
TEST(C2CMessages, EncodeAichAnswerV2RecoveryData){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  AICHHash master = AICHHash::from_bytes(sha1_from_hex("00112233445566778899aabbccddeeff00112233"));
  AICHProofHash p;
  p.identifier = 7;
  p.hash = sha1_from_hex("aabbccddeeff00112233445566778899aabbccdd");
  auto out=encode_aich_answer(h, master, 2, std::array{p});
  ByteWriter w;
  w.hash16(h);
  w.u16(2);
  w.hash20(master.bytes());
  w.u16(1);
  w.u16(7);
  w.hash20(p.hash);
  w.u16(0);
  EXPECT_EQ(out, w.take());
}
TEST(C2CMessages, EncodeEndOfDownload){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  EXPECT_EQ(encode_end_of_download(h), hex("00112233445566778899aabbccddeeff"));
}
TEST(C2CMessages, EncodeCancelTransfer){
  EXPECT_TRUE(encode_cancel_transfer().empty());
}

#include <zlib.h>
static std::vector<std::byte> zlib_compress(std::span<const std::byte> in){
  uLongf bound = compressBound(static_cast<uLong>(in.size()));
  std::vector<std::byte> out(bound);
  uLongf outlen = bound;
  compress(reinterpret_cast<Bytef*>(out.data()),&outlen,
           reinterpret_cast<const Bytef*>(in.data()), static_cast<uLong>(in.size()));
  out.resize(outlen);
  return out;
}
TEST(C2CMessages, DecodeHelloAnswer){
  ByteWriter w;
  w.hash16(*UserHash::from_hex("0123456789abcdeffedcba9876543210"));
  w.u32(0x01020304u);
  w.u16(0x1234u);
  w.u32(2);
  w.u8(0x82);
  w.u8(tag::CT_NAME);
  w.string16("peer");
  w.u8(0x83);
  w.u8(tag::CT_VERSION);
  w.u32(0x3C);
  w.u32(0x0100007Fu);
  w.u16(0x4662u);
  auto out=decode_hello_answer(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->nickname, "peer");
  EXPECT_EQ(out->version, 0x3Cu);
  EXPECT_TRUE(out->server_ip.has_value());
  EXPECT_EQ(out->server_ip->host(), 0x7F000001u);
  EXPECT_EQ(out->server_port, 0x4662u);
}
TEST(C2CMessages, DecodeHello){
  // OP_HELLO 帧 = [0x10] + body(hash+id+port+tagcount+tags+server_ip+server_port)。
  ByteWriter w;
  w.u8(0x10);
  w.hash16(*UserHash::from_hex("0123456789abcdeffedcba9876543210"));
  w.u32(0x01020304u);
  w.u16(0x1234u);
  w.u32(2);
  w.u8(0x82); w.u8(tag::CT_NAME); w.string16("peer");
  w.u8(0x83); w.u8(tag::CT_VERSION); w.u32(0x3C);
  w.u32(0x0100007Fu);   // server_ip 127.0.0.1: aMule WriteUInt32(LE of a-LOW-byte 0x0100007F) → 线字节 [7F,00,00,01]
  w.u16(0x4662u);
  auto out=decode_hello(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->nickname, "peer");
  EXPECT_EQ(out->version, 0x3Cu);
  EXPECT_TRUE(out->server_ip.has_value());
  EXPECT_EQ(out->server_ip->host(), 0x7F000001u);
  EXPECT_EQ(out->server_port, 0x4662u);
}
TEST(C2CMessages, DecodeHelloRejectsBadHashsize){
  // 首字节非 0x10 → aMule ProcessHelloPacket 抛出(if(16!=hashsize));我们返回 unsupported_version。
  ByteWriter w;
  w.u8(0x11);
  w.hash16(*UserHash::from_hex("0123456789abcdeffedcba9876543210"));
  auto out=decode_hello(w.take());
  EXPECT_FALSE(out.has_value());
}
TEST(C2CMessages, DecodeFileStatus){
  ByteWriter w;
  w.hash16(*FileHash::from_hex("00112233445566778899aabbccddeeff"));
  w.u16(9);
  w.u8(0xFF);
  w.u8(0x01);
  auto out=decode_file_status(w.take());
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->parts.size(), 9u);
  for(int i=0;i<9;++i) EXPECT_TRUE(out->parts[i]) << "part " << i;
}
TEST(C2CMessages, DecodeHashsetAnswer){
  ByteWriter w;
  auto fh = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  w.hash16(fh);                       // aMule SendHashsetPacket 前导文件 hash
  w.u16(2);
  w.hash16(*PartHash::from_hex("11111111111111111111111111111111"));
  w.hash16(*PartHash::from_hex("22222222222222222222222222222222"));
  auto out=decode_hashset_answer(fh, w.take());
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->size(), 2u);
}
TEST(C2CMessages, DecodeHashsetAnswerSinglePart){
  ByteWriter w;
  auto fh = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  w.hash16(fh);
  w.u16(0);
  auto out=decode_hashset_answer(fh, w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_TRUE(out->empty());
}
TEST(C2CMessages, DecodeHashsetAnswerHashMismatch){
  // aMule ProcessHashsetAnswer: 前导 file_hash 与请求不符即丢弃。引擎返回 hash_mismatch。
  ByteWriter w;
  w.hash16(*FileHash::from_hex("ffffffffffffffffffffffffffffffff"));
  w.u16(1);
  w.hash16(*PartHash::from_hex("11111111111111111111111111111111"));
  auto expected = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  auto out=decode_hashset_answer(expected, w.take());
  ASSERT_FALSE(out.has_value());
  EXPECT_EQ(out.error(), make_error_code(errc::hash_mismatch));
}
TEST(C2CMessages, DecodeReqFilenameAnswer){
  ByteWriter w;
  w.hash16(*FileHash::from_hex("00112233445566778899aabbccddeeff"));
  w.u32(3);
  w.blob(bytes({'a','b','c'}));
  auto out=decode_req_filename_answer(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->name, "abc");
}
TEST(C2CMessages, DecodeReqFilenameAnswerWithAmuleU16String){
  auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  ByteWriter w;
  w.hash16(h);
  w.u16(23);
  w.blob(bytes({'e','d','2','k','_','p','5','_','l','i','v','e','_','s','o','u','r','c','e','.','b','i','n'}));
  auto out=decode_req_filename_answer(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->hash, h);
  EXPECT_EQ(out->name, "ed2k_p5_live_source.bin");
}
TEST(C2CMessages, DecodeQueueRanking){
  ByteWriter w;
  w.u16(42);
  auto out=decode_queue_ranking(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, 42u);
}
TEST(C2CMessages, DecodeSendingPart){
  ByteWriter w;
  w.hash16(*FileHash::from_hex("00112233445566778899aabbccddeeff"));
  w.u32(100);
  w.u32(200);
  w.blob(bytes({1,2,3}));
  auto out=decode_sending_part(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->start, 100u);
  EXPECT_EQ(out->end, 200u);
  EXPECT_EQ(out->data, bytes({1,2,3}));
}
TEST(C2CMessages, DecodeCompressedPart){
  auto plain = bytes({10,20,30,40,50});
  auto comp = zlib_compress(plain);
  ByteWriter w;
  w.hash16(*FileHash::from_hex("00112233445566778899aabbccddeeff"));
  w.u32(100);
  w.u32(200);
  w.blob(comp);
  auto out=decode_compressed_part(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->data, plain);
}
TEST(C2CMessages, DecodeFileReqAnsNoFil){
  ByteWriter w;
  w.hash16(*FileHash::from_hex("00112233445566778899aabbccddeeff"));
  auto out=decode_file_req_ans_no_fil(w.take());
  ASSERT_TRUE(out.has_value());
}
TEST(C2CMessages, DecodeSendingPartTruncated){
  EXPECT_FALSE(decode_sending_part(bytes({1,2,3})).has_value());
}

TEST(C2CMessages, EncodeAichFileHashReq){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  auto out=encode_aich_file_hash_req(h);
  EXPECT_EQ(out, hex("00112233445566778899aabbccddeeff"));
  EXPECT_EQ(out.size(), 16u);
}
TEST(C2CMessages, DecodeAichFileHashAns){
  ByteWriter w;
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  w.hash16(h);
  w.hash20(sha1_from_hex("00112233445566778899aabbccddeeff00112233"));
  auto out=decode_aich_file_hash_ans(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->bytes(), sha1_from_hex("00112233445566778899aabbccddeeff00112233"));
}
TEST(C2CMessages, EncodeAichRequest){
  // aMule SendAICHRequest 顺序: file_hash(16) + part_index(u16 LE) + master_hash(20) = 38B
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  AICHHash master = AICHHash::from_bytes(sha1_from_hex("00112233445566778899aabbccddeeff00112233"));
  auto out=encode_aich_request(h, master, 42);
  std::vector<std::byte> want=hex("00112233445566778899aabbccddeeff");
  want.push_back(std::byte(42)); want.push_back(std::byte(0));   // part_index LE
  auto m = hex("00112233445566778899aabbccddeeff00112233");
  want.insert(want.end(), m.begin(), m.end());
  EXPECT_EQ(out.size(), 38u);
  EXPECT_EQ(out, want);
}
TEST(C2CMessages, DecodeAichAnswerV2RecoveryData){
  // 帧 = file_hash(16) + part_index(2) + master_hash(20) + V2(count16 + [ident16+hash]×n + count32(0))
  ByteWriter w;
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  AICHHash master = AICHHash::from_bytes(sha1_from_hex("00112233445566778899aabbccddeeff00112233"));
  w.hash16(h); w.u16(7); w.hash20(master.bytes());
  w.u16(2);                                                // count16 = 2
  w.u16(0x0001); w.hash20(sha1_from_hex("00112233445566778899aabbccddeeff00112233"));
  w.u16(0x0002); w.hash20(sha1_from_hex("aabbccddeeff00112233445566778899aabbccdd"));
  w.u16(0);                                                // count32 = 0 (非大文件)
  auto out=decode_aich_answer(w.take());
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->hashes.size(), 2u);
  EXPECT_EQ(out->hashes[0].identifier, 0x0001u);
  EXPECT_EQ(out->hashes[1].identifier, 0x0002u);
  EXPECT_EQ(out->hashes[0].hash, sha1_from_hex("00112233445566778899aabbccddeeff00112233"));
  EXPECT_EQ(out->hashes[1].hash, sha1_from_hex("aabbccddeeff00112233445566778899aabbccdd"));
}
TEST(C2CMessages, DecodeAichAnswerTruncated){
  // 缺 master_hash/ V2 头 → buffer_underflow
  ByteWriter w;
  w.hash16(*FileHash::from_hex("00112233445566778899aabbccddeeff"));
  w.u16(0);   // 仅 part_index,缺 master_hash
  EXPECT_FALSE(decode_aich_answer(w.take()).has_value());
}
TEST(C2CMessages, EncodeRequestPartsI64){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  auto out=encode_request_parts_i64(h, {100, 200, 300}, {150, 250, 350});
  std::vector<std::byte> want=hex("00112233445566778899aabbccddeeff");
  for(uint64_t s : {100,200,300}) {
    want.push_back(std::byte(s&0xff)); want.push_back(std::byte((s>>8)&0xff));
    want.push_back(std::byte((s>>16)&0xff)); want.push_back(std::byte((s>>24)&0xff)); want.push_back(std::byte((s>>32)&0xff));
    want.push_back(std::byte((s>>40)&0xff)); want.push_back(std::byte((s>>48)&0xff)); want.push_back(std::byte((s>>56)&0xff));
  }
  for(uint64_t e : {150,250,350}) {
    want.push_back(std::byte(e&0xff)); want.push_back(std::byte((e>>8)&0xff));
    want.push_back(std::byte((e>>16)&0xff)); want.push_back(std::byte((e>>24)&0xff));
    want.push_back(std::byte((e>>32)&0xff)); want.push_back(std::byte((e>>40)&0xff));
    want.push_back(std::byte((e>>48)&0xff)); want.push_back(std::byte((e>>56)&0xff));
  }
  EXPECT_EQ(out, want);
}
TEST(C2CMessages, DecodeSendingPartI64){
  ByteWriter w;
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  w.hash16(h);
  w.u64(100);
  w.u64(200);
  w.blob(bytes({1,2,3,4,5}));
  auto out=decode_sending_part_i64(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->start, 100u);
  EXPECT_EQ(out->end, 200u);
  EXPECT_EQ(out->data, bytes({1,2,3,4,5}));
}
// P4c-3-3: peer::Block is now u64. Offsets beyond 4 GiB must survive decode
// without the silent u32 narrowing decode_sending_part_i64 had when
// Block.start/end were u32 (the >4GiB corruption root cause, P4c-3 spec §3.1).
// Full >4GiB block-offset e2e is exercised in M4.
TEST(C2CMessages, DecodeSendingPartI64Beyond4GiB){
  ByteWriter w;
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  w.hash16(h);
  w.u64(0x100000000ULL);                 // exactly 4 GiB
  w.u64(0x100000000ULL + 184320);        // one AICH block past 4 GiB
  w.blob(bytes({1,2,3}));
  auto out=decode_sending_part_i64(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->start, 0x100000000ULL);
  EXPECT_EQ(out->end,   0x100000000ULL + 184320);
}
TEST(C2CMessages, DecodeCompressedPartI64){
  auto plain = bytes({10,20,30,40,50});
  auto comp = zlib_compress(plain);
  ByteWriter w;
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  w.hash16(h);
  w.u64(100);
  w.u64(200);
  w.blob(comp);
  auto out=decode_compressed_part_i64(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->data, plain);
}
TEST(C2CMessages, DecodeSendingPartI64Truncated){
  EXPECT_FALSE(decode_sending_part_i64(bytes({1,2,3,4})).has_value());
}
