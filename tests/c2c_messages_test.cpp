#include <gtest/gtest.h>
#include "ed2k/peer/c2c_messages.hpp"
using namespace ed2k; using namespace ed2k::peer; using namespace ed2k::server;
static std::vector<std::byte> bytes(std::initializer_list<int> xs){
  std::vector<std::byte> v; for(int x:xs) v.push_back(std::byte(x)); return v;
}
static std::vector<std::byte> hex(std::string_view h){
  std::vector<std::byte> v;
  auto val=[&](char c)->int{ return c<='9'? c-'0' : (c|0x20)-'a'+10; };
  for(std::size_t i=0;i+1<h.size();i+=2) v.push_back(std::byte(val(h[i])*16+val(h[i+1])));
  return v;
}
TEST(C2CMessages, EncodeHello){
  HelloInfo h; h.user_hash=*UserHash::from_hex("0123456789abcdeffedcba9876543210");
  h.client_id=0x01020304u; h.port=0x1234u; h.nickname="u"; h.version=0x3C;
  auto out=encode_hello(h);
  std::vector<std::byte> want;
  auto app=[&](const std::vector<std::byte>& b){ want.insert(want.end(),b.begin(),b.end()); };
  app(hex("0123456789abcdeffedcba9876543210"));  // userhash
  app(bytes({0x04,0x03,0x02,0x01}));              // clientID LE
  app(bytes({0x34,0x12}));                          // port LE
  app(bytes({2,0,0,0}));                            // tagcount=2
  app(bytes({0x82,tag::CT_NAME, 0x01,0x00,'u'}));  // string tag CT_NAME
  app(bytes({0x83,tag::CT_VERSION, 0x3c,0x00,0x00,0x00}));  // u32 tag CT_VERSION
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
  for(int s : {100,200,300}) { auto b=bytes({s&0xff,(s>>8)&0xff,0,0}); want.insert(want.end(),b.begin(),b.end()); }
  for(int e : {150,250,350}) { auto b=bytes({e&0xff,(e>>8)&0xff,0,0}); want.insert(want.end(),b.begin(),b.end()); }
  EXPECT_EQ(out, want);
}
TEST(C2CMessages, EncodeEndOfDownload){
  auto h=*FileHash::from_hex("00112233445566778899aabbccddeeff");
  EXPECT_EQ(encode_end_of_download(h), hex("00112233445566778899aabbccddeeff"));
}
TEST(C2CMessages, EncodeCancelTransfer){
  EXPECT_TRUE(encode_cancel_transfer().empty());
}
