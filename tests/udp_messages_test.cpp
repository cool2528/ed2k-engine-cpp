#include <gtest/gtest.h>
#include "ed2k/server/udp_messages.hpp"
#include "ed2k/server/search_query.hpp"
using namespace ed2k; using namespace ed2k::server;
static std::vector<std::byte> bytes(std::initializer_list<int> xs){
  std::vector<std::byte> v; for(int x:xs) v.push_back(std::byte(x)); return v;
}
static std::vector<std::byte> hex(std::string_view h){
  std::vector<std::byte> v;
  auto val=[&](char c)->int{ return c<='9'? c-'0' : (c|0x20)-'a'+10; };
  for(std::size_t i=0;i+1<h.size();i+=2) v.push_back(std::byte(val(h[i])*16+val(h[i+1])));
  return v;
}
TEST(UdpMessages, EncodeGetSourcesReq){
  auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  std::vector<std::byte> want = hex("00112233445566778899aabbccddeeff");
  auto s = bytes({100,0,0,0}); want.insert(want.end(), s.begin(), s.end());
  EXPECT_EQ(encode_get_sources_req(h, 100), want);
}
TEST(UdpMessages, EncodeServerStatusReq){
  EXPECT_EQ(encode_server_status_req(0x12345678u), bytes({0x78,0x56,0x34,0x12}));
}
TEST(UdpMessages, EncodeServerListReq){
  EXPECT_EQ(encode_server_list_req(IPv4{0x01020304u}, 0x1234u),
            bytes({0x01,0x02,0x03,0x04, 0x34,0x12}));
}
TEST(UdpMessages, EncodeServerDescReq){
  EXPECT_EQ(encode_server_desc_req(0xF0FF1234u), bytes({0x34,0x12,0xFF,0xF0}));
}
TEST(UdpMessages, EncodeGlobSearchReqDelegates){
  SearchExpr k = Keyword{"foo"};
  EXPECT_EQ(encode_glob_search_req(k), serialize_search(k));
}

#include "ed2k/codec/byte_io.hpp"
using ed2k::codec::ByteWriter;

static std::vector<std::byte> search_item(std::string_view name){
  ByteWriter w;
  auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  w.hash16(h); w.u32(0xDDCCBBAAu); w.u16(0x1234u); w.u32(1);
  w.u8(0x82); w.u8(tag::FT_FILENAME); w.string16(name);
  return w.take();
}
TEST(UdpMessages, DecodeGlobSearchResConcat){
  std::vector<std::byte> d = search_item("foo");
  d.push_back(std::byte(0xE3)); d.push_back(std::byte(udpop::GLOBSEARCHRES));
  auto it2 = search_item("bar"); d.insert(d.end(), it2.begin(), it2.end());
  auto out = decode_glob_search_res(d);
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->items.size(), 2u);
  EXPECT_EQ(out->items[0].name, "foo");
  EXPECT_EQ(out->items[1].name, "bar");
}
TEST(UdpMessages, DecodeGlobSearchResSingle){
  auto d = search_item("solo");
  auto out = decode_glob_search_res(d);
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->items.size(), 1u);
  EXPECT_EQ(out->items[0].name, "solo");
}
TEST(UdpMessages, DecodeGlobFoundSourcesConcat){
  ByteWriter w;
  auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  w.hash16(h); w.u8(1); w.u32(0x01000000u); w.u16(0x1234u);          // 组1: HighID 源
  w.u8(0xE3); w.u8(udpop::GLOBFOUNDSOURCES);
  w.hash16(h); w.u8(1); w.u32(5u); w.u16(0x5678u);                     // 组2: LowID 源
  auto out = decode_glob_found_sources(w.take());
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->size(), 2u);
  EXPECT_FALSE((*out)[0].sources[0].low_id());
  EXPECT_TRUE((*out)[1].sources[0].low_id());
}
TEST(UdpMessages, DecodeServerStatMinimal){
  ByteWriter w; w.u32(0xCAFEBABEu); w.u32(100); w.u32(5000);          // challenge + users + files (12B)
  auto out = decode_server_stat(w.take(), 0xCAFEBABEu);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->users, 100u); EXPECT_EQ(out->files, 5000u);
  EXPECT_EQ(out->max_users, 0u);                                      // 可选字段未发
}
TEST(UdpMessages, DecodeServerStatFull){
  ByteWriter w;
  w.u32(0xCAFEBABEu); w.u32(100); w.u32(5000);                        // 12
  w.u32(2000);                                                        // max_users (16)
  w.u32(100); w.u32(50000);                                           // soft/hard (24)
  w.u32(0x18);                                                        // udp_flags (28)
  w.u32(5);                                                           // low_id_users (32)
  w.u16(4672); w.u16(0); w.u32(0xABCDEF01u);                          // obf ports + udp_key (40)
  auto out = decode_server_stat(w.take(), 0xCAFEBABEu);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->max_users, 2000u);
  EXPECT_EQ(out->udp_flags, 0x18u);
  EXPECT_EQ(out->udp_key, 0xABCDEF01u);
}
TEST(UdpMessages, DecodeServerStatChallengeMismatch){
  ByteWriter w; w.u32(0xCAFEBABEu); w.u32(1); w.u32(2);
  auto out = decode_server_stat(w.take(), 0xDEADBEEFu);
  EXPECT_FALSE(out.has_value());
  EXPECT_EQ(out.error(), make_error_code(errc::server_protocol_error));
}
TEST(UdpMessages, DecodeServerList){
  ByteWriter w; w.u8(2);
  w.u32_be(0x01020304u); w.u16(0x1234u);
  w.u32_be(0x05060708u); w.u16(0x5678u);
  auto out = decode_server_list(w.take());
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->size(), 2u);
  EXPECT_EQ((*out)[0].first.value, 0x01020304u);
  EXPECT_EQ((*out)[1].second, 0x5678u);
}
TEST(UdpMessages, DecodeServerDescNewFormat){
  std::uint32_t challenge = 0x1234F0FFu;                              // 低2字节=0xF0FF
  ByteWriter w;
  w.u32(challenge);                                                   // data[0..1]=0xFF,0xF0 → len=0xF0FF
  w.u32(2);                                                           // tagcount
  w.u8(0x82); w.u8(tag::ST_SERVERNAME);    w.string16("n");
  w.u8(0x82); w.u8(tag::ST_DESCRIPTION);   w.string16("d");
  auto out = decode_server_desc(w.take(), challenge);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->name, "n");
  EXPECT_EQ(out->description, "d");
}
TEST(UdpMessages, DecodeServerDescOldFormat){
  ByteWriter w;
  w.string16("des");                                                  // desc 在前 (data[0..1]=0x0003, !=0xF0FF)
  w.string16("nm");                                                   // name 在后
  auto out = decode_server_desc(w.take(), 0);                        // 旧格式不用 challenge
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->description, "des");
  EXPECT_EQ(out->name, "nm");
}
TEST(UdpMessages, DecodeServerDescChallengeMismatch){
  std::uint32_t sent = 0x1234F0FFu;
  ByteWriter w; w.u32(sent); w.u32(0);
  auto out = decode_server_desc(w.take(), 0x9999F0FFu);              // 低2字节同为 0xF0FF → 新格式
  EXPECT_FALSE(out.has_value());
  EXPECT_EQ(out.error(), make_error_code(errc::server_protocol_error));
}
TEST(UdpMessages, DecodeInvalidLowId){
  ByteWriter w; w.u32(0x00001234u);
  auto out = decode_invalid_low_id(w.take());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, 0x00001234u);
}
TEST(UdpMessages, DecodeGlobSearchResTruncated){
  EXPECT_FALSE(decode_glob_search_res(bytes({0,0,0})).has_value());  // 不完整条目
}
