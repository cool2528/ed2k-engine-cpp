#include <gtest/gtest.h>
#include <array>
#include "crypto/sha1.hpp"
#include "ed2k/peer/c2c_messages.hpp"
using namespace ed2k; using namespace ed2k::peer; using namespace ed2k::server;

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
  app(bytes({2,0,0,0}));
  app(bytes({0x82,tag::CT_NAME, 0x01,0x00,'u'}));
  app(bytes({0x83,tag::CT_VERSION, 0x3c,0x00,0x00,0x00}));
  EXPECT_EQ(out, want);
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
TEST(C2CMessages, EncodeStartUpload){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  EXPECT_EQ(encode_start_upload(h), hex("00112233445566778899aabbccddeeff"));
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
TEST(C2CMessages, EncodeEndOfDownload){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  EXPECT_EQ(encode_end_of_download(h), hex("00112233445566778899aabbccddeeff"));
}
TEST(C2CMessages, EncodeCancelTransfer){
  EXPECT_TRUE(encode_cancel_transfer().empty());
}

#include "ed2k/codec/byte_io.hpp"
#include <zlib.h>
using ed2k::codec::ByteWriter;
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
  w.u32(0x7F000001u);
  w.u16(0x4662u);
  auto out=decode_hello_answer(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->nickname, "peer");
  EXPECT_EQ(out->version, 0x3Cu);
  EXPECT_TRUE(out->server_ip.has_value());
  EXPECT_EQ(out->server_ip->value, 0x7F000001u);
  EXPECT_EQ(out->server_port, 0x4662u);
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
  w.u16(2);
  w.hash16(*PartHash::from_hex("11111111111111111111111111111111"));
  w.hash16(*PartHash::from_hex("22222222222222222222222222222222"));
  auto out=decode_hashset_answer(w.take());
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->size(), 2u);
}
TEST(C2CMessages, DecodeHashsetAnswerSinglePart){
  ByteWriter w;
  w.u16(0);
  auto out=decode_hashset_answer(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_TRUE(out->empty());
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
