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
            bytes({0x04,0x03,0x02,0x01, 0x34,0x12}));
}
TEST(UdpMessages, EncodeServerDescReq){
  EXPECT_EQ(encode_server_desc_req(0xF0FF1234u), bytes({0x34,0x12,0xFF,0xF0}));
}
TEST(UdpMessages, EncodeGlobSearchReqDelegates){
  SearchExpr k = Keyword{"foo"};
  EXPECT_EQ(encode_glob_search_req(k), serialize_search(k));
}
