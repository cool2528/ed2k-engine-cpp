#include <gtest/gtest.h>
#include "ed2k/server/messages.hpp"
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

TEST(ServerMessages, EncodeLogin){
  LoginParams p;
  p.user_hash = *UserHash::from_hex("0123456789abcdeffedcba9876543210");
  p.client_port = 0x1234;
  p.nickname = "test";
  p.version = 0x3C;
  p.server_flags = srvflag::ZLIB|srvflag::NEWTAGS|srvflag::UNICODE|srvflag::LARGEFILES;  // 0x0119
  auto out = encode_login(p);
  std::vector<std::byte> want;
  auto app=[&](const std::vector<std::byte>& b){ want.insert(want.end(), b.begin(), b.end()); };
  app(hex("0123456789abcdeffedcba9876543210"));  // userhash
  app(bytes({0,0,0,0}));                          // clientID = 0
  app(bytes({0x34,0x12}));                        // port 0x1234 LE
  app(bytes({3,0,0,0}));                          // tagcount = 3
  app(bytes({0x82,tag::CT_NAME, 0x04,0x00,'t','e','s','t'}));            // string tag CT_NAME
  app(bytes({0x83,tag::CT_VERSION, 0x3c,0x00,0x00,0x00}));               // u32 tag CT_VERSION
  app(bytes({0x83,tag::CT_SERVER_FLAGS, 0x19,0x01,0x00,0x00}));          // u32 tag CT_SERVER_FLAGS
  EXPECT_EQ(out, want);
}
TEST(ServerMessages, EncodeGetSources){
  auto h = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  auto out = encode_get_sources(h, 100);
  std::vector<std::byte> want = hex("00112233445566778899aabbccddeeff");
  auto s = bytes({100,0,0,0});
  want.insert(want.end(), s.begin(), s.end());
  EXPECT_EQ(out, want);
}
TEST(ServerMessages, EncodeCallbackRequest){
  EXPECT_EQ(encode_callback_request(0x12345678), bytes({0x78,0x56,0x34,0x12}));
}
TEST(ServerMessages, EncodeGetServerList){
  EXPECT_TRUE(encode_get_server_list().empty());
}
TEST(ServerMessages, EncodeSearchDelegates){
  SearchExpr k = Keyword{"foo"};
  EXPECT_EQ(encode_search(k), serialize_search(k));
}

TEST(ServerMessages, DecodeIdChangeHighId){
  auto out = decode_id_change(bytes({0,0,0,0x01, 0x19,0x01,0x00,0x00}));   // id=0x01000000, flags=0x0119
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->id, 0x01000000u);
  EXPECT_EQ(out->flags, 0x0119u);
  EXPECT_TRUE(out->high_id());
}
TEST(ServerMessages, DecodeIdChangeLowIdNoFlags){
  auto out = decode_id_change(bytes({5,0,0,0}));                            // id=5, 无 flags
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->id, 5u);
  EXPECT_EQ(out->flags, 0u);
  EXPECT_FALSE(out->high_id());
}
TEST(ServerMessages, DecodeIdChangeTruncated){
  EXPECT_FALSE(decode_id_change(bytes({1,2,3})).has_value());
}
TEST(ServerMessages, DecodeServerStatus){
  auto out = decode_server_status(bytes({16,0,0,0, 32,0,0,0}));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->users, 16u);
  EXPECT_EQ(out->files, 32u);
}
TEST(ServerMessages, DecodeServerMessage){
  auto out = decode_server_message(bytes({5,0,'h','e','l','l','o'}));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, "hello");
}
TEST(ServerMessages, DecodeServerList){
  auto out = decode_server_list(bytes({2, 1,2,3,4, 0x34,0x12, 5,6,7,8, 0x78,0x56}));
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->size(), 2u);
  EXPECT_EQ((*out)[0].first.host(), 0x01020304u);
  EXPECT_EQ((*out)[0].second, 0x1234u);
  EXPECT_EQ((*out)[1].first.host(), 0x05060708u);
}
TEST(ServerMessages, DecodeCallbackRequested){
  auto out = decode_callback_requested(bytes({0x7F,0,0,1, 0x34,0x12}));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->ip.host(), 0x7F000001u);
  EXPECT_EQ(out->port, 0x1234u);
}
TEST(ServerMessages, DecodeFoundSources){
  std::vector<std::byte> d = hex("00112233445566778899aabbccddeeff");
  d.push_back(std::byte(2));
  auto app=[&](std::initializer_list<int> xs){ for(int x:xs) d.push_back(std::byte(x)); };
  app({0,0,0,0x01, 0x34,0x12});        // HighID 源
  app({5,0,0,0, 0x78,0x56});           // LowID 源
  auto out = decode_found_sources(d);
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->sources.size(), 2u);
  EXPECT_FALSE(out->sources[0].low_id());
  EXPECT_TRUE(out->sources[1].low_id());
}
TEST(ServerMessages, DecodeSearchResult){
  std::vector<std::byte> d;
  auto app=[&](std::initializer_list<int> xs){ for(int x:xs) d.push_back(std::byte(x)); };
  app({1,0,0,0});                                          // count=1
  auto h = hex("00112233445566778899aabbccddeeff");
  d.insert(d.end(), h.begin(), h.end());                   // hash
  app({0xAA,0xBB,0xCC,0xDD});                              // client_id
  app({0x34,0x12});                                         // port
  app({2,0,0,0});                                           // tagcount=2
  app({0x82,tag::FT_FILENAME, 0x03,0x00,'f','o','o'});     // string tag "foo"
  app({0x83,tag::FT_FILESIZE, 100,0,0,0});                 // u32 tag size=100
  auto out = decode_search_result(d);
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->size(), 1u);
  EXPECT_EQ((*out)[0].name, "foo");
  EXPECT_EQ((*out)[0].size, 100u);
  EXPECT_EQ((*out)[0].client_id, 0xDDCCBBAAu);
  EXPECT_EQ((*out)[0].tags.size(), 2u);
}
TEST(ServerMessages, DecodeSearchResultTruncated){
  EXPECT_FALSE(decode_search_result(bytes({1,0,0,0, 0,0,0})).has_value());
}
TEST(ServerMessages, LoginRoundTrip){
  LoginParams p;
  p.user_hash = *UserHash::from_hex("0123456789abcdeffedcba9876543210");
  p.client_port = 4662; p.nickname = "rt"; p.version = 0x3C;
  p.server_flags = srvflag::ZLIB|srvflag::UNICODE;
  auto payload = encode_login(p);
  codec::ByteReader r(payload);
  (void)r.hash16(); (void)r.u32(); (void)r.u16();
  auto tags = codec::read_taglist(r, r.u32());
  ASSERT_TRUE(tags.has_value());
  ASSERT_EQ(tags->size(), 3u);
  EXPECT_EQ(std::get<std::string>((*tags)[0].value), "rt");
}

TEST(ServerMessages, DecodeServerIdent){
  std::vector<std::byte> d = hex("00112233445566778899aabbccddeeff");   // MD4Hash(16)
  auto app=[&](std::initializer_list<int> xs){ for(int x:xs) d.push_back(std::byte(x)); };
  app({0x7F,0,0,1});                                                       // ip 127.0.0.1 线序 (a.b.c.d)
  app({0x34,0x12});                                                        // port 0x1234 LE
  app({2,0,0,0});                                                          // tagcount = 2
  app({0x82,tag::ST_SERVERNAME,  0x04,0x00,'n','a','m','e'});             // string tag "name"
  app({0x82,tag::ST_DESCRIPTION, 0x04,0x00,'d','e','s','c'});             // string tag "desc"
  auto out = decode_server_ident(d);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->hash, *MD4Hash::from_hex("00112233445566778899aabbccddeeff"));
  EXPECT_EQ(out->ip.host(), 0x7F000001u);
  EXPECT_EQ(out->port, 0x1234u);
  EXPECT_EQ(out->name, "name");
  EXPECT_EQ(out->description, "desc");
}
