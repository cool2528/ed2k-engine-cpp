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
