#include <gtest/gtest.h>
#include <array>
#include <cstdio>
#include <fstream>
#include <filesystem>
#include "ed2k/metfile/server_met.hpp"
#include "ed2k/codec/byte_io.hpp"
using namespace ed2k;

TEST(ServerMet, RoundTripModelEqual){
  ServerList in;
  ServerEntry a; a.ip=*IPv4::from_dotted("10.0.0.5"); a.port=4661;
  a.name="Test Server"; a.description="desc"; a.max_users=1000;
  ServerEntry b; b.ip=*IPv4::from_dotted("10.0.0.6"); b.port=5000; b.name="S2";
  in.servers={a,b};
  auto bytes=write_server_met(in);
  auto out=parse_server_met(bytes);
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->servers.size(),2u);
  EXPECT_EQ(out->servers[0].ip, a.ip);
  EXPECT_EQ(out->servers[0].port, a.port);
  EXPECT_EQ(out->servers[0].name, a.name);
  EXPECT_EQ(out->servers[0].description, a.description);
  EXPECT_EQ(out->servers[0].max_users, a.max_users);
  EXPECT_EQ(out->servers[1].name, "S2");
  // Whole-entry comparison now compiles (ServerEntry's defaulted <=> is real
  // because codec::Tag is now three-way comparable).
  EXPECT_EQ(out->servers[0], a);
}
TEST(ServerMet, RejectsBadMagic){
  std::array<std::byte,5> bad{ std::byte{0x99}, std::byte{0},std::byte{0},std::byte{0},std::byte{0} };
  EXPECT_FALSE(parse_server_met(bad).has_value());
}
TEST(ServerMet, RejectsTruncated){
  // header 0x0E + count=1 但无服务器数据
  std::array<std::byte,5> t{ std::byte{0x0E}, std::byte{1},std::byte{0},std::byte{0},std::byte{0} };
  EXPECT_FALSE(parse_server_met(t).has_value());
}

// Unknown tags must survive a round-trip via the `extra` field.
TEST(ServerMet, PreservesUnknownTags){
  ServerList in;
  ServerEntry a; a.ip=*IPv4::from_dotted("192.168.1.1"); a.port=4242; a.name="Srv";
  codec::Tag custom; custom.name_id=0x99; custom.value=std::uint64_t(7);
  codec::Tag named;  named.name_str="x-custom"; named.value=std::string("hello");
  a.extra = { custom, named };
  in.servers = { a };
  auto bytes=write_server_met(in);
  auto out=parse_server_met(bytes);
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->servers.size(),1u);
  ASSERT_EQ(out->servers[0].extra.size(),2u);
  // Tag has no operator==, so compare the preserved tags field-by-field.
  const auto& g0 = out->servers[0].extra[0];
  EXPECT_EQ(g0.name_id, custom.name_id);
  ASSERT_TRUE(std::holds_alternative<std::uint64_t>(g0.value));
  EXPECT_EQ(std::get<std::uint64_t>(g0.value), std::uint64_t(7));
  const auto& g1 = out->servers[0].extra[1];
  EXPECT_TRUE(g1.has_string_name());
  EXPECT_EQ(g1.name_str, named.name_str);
  ASSERT_TRUE(std::holds_alternative<std::string>(g1.value));
  EXPECT_EQ(std::get<std::string>(g1.value), std::string("hello"));
}

// Graceful degradation: an unsupported tag TYPE (e.g. Float 0x04, not
// implemented by codec::read_tag) must produce a clean error, not a crash.
TEST(ServerMet, UnsupportedTagTypeErrorsNoCrash){
  codec::ByteWriter w;
  w.u8(0x0E);            // valid magic
  w.u32(1);              // 1 server
  w.u32(0x0100007F);     // ip
  w.u16(4661);           // port
  w.u32(1);              // 1 tag
  w.u8(0x8A);            // type 0x0A (undefined, unsupported) | NameFlag 0x80
  w.u8(0x01);            // name_id
  w.u32(0);              // some payload bytes
  auto bytes=w.take();
  auto out=parse_server_met(bytes); // must not crash
  EXPECT_FALSE(out.has_value());
}

// On-disk round-trip: write bytes to a temp file, read them back, parse.
// Stands in for "parse a real server.met" at unit level (the CLI path).
TEST(ServerMet, OnDiskRoundTrip){
  ServerList in;
  ServerEntry a; a.ip=*IPv4::from_dotted("10.0.0.5"); a.port=4661;
  a.name="Disk Server"; a.description="on-disk"; a.max_users=500;
  in.servers={a};
  auto bytes=write_server_met(in);

  auto path = std::filesystem::temp_directory_path() / "ed2k_server_met_test.met";
  {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
  }
  std::vector<std::byte> read_back;
  {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    auto sz = static_cast<std::size_t>(f.tellg());
    f.seekg(0);
    read_back.resize(sz);
    f.read(reinterpret_cast<char*>(read_back.data()),
           static_cast<std::streamsize>(sz));
  }
  std::filesystem::remove(path);

  auto out=parse_server_met(read_back);
  ASSERT_TRUE(out.has_value());
  ASSERT_EQ(out->servers.size(),1u);
  EXPECT_EQ(out->servers[0].ip, a.ip);
  EXPECT_EQ(out->servers[0].port, a.port);
  EXPECT_EQ(out->servers[0].name, a.name);
  EXPECT_EQ(out->servers[0].description, a.description);
  EXPECT_EQ(out->servers[0].max_users, a.max_users);
}
