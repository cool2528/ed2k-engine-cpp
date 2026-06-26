#include <gtest/gtest.h>
#include <string>
#include "crypto/md4.hpp"
static std::string hex(std::array<std::byte,16> h) {
  static const char* k="0123456789abcdef"; std::string s;
  for (auto b : h){ auto v=std::to_integer<unsigned>(b); s+=k[v>>4]; s+=k[v&15]; }
  return s;
}
static std::array<std::byte,16> md4s(std::string_view in){
  return ed2k::crypto::md4({reinterpret_cast<const std::byte*>(in.data()), in.size()});
}
TEST(MD4, Rfc1320Vectors) {
  EXPECT_EQ(hex(md4s("")),    "31d6cfe0d16ae931b73c59d7e0c089c0");
  EXPECT_EQ(hex(md4s("a")),   "bde52cb31de33e46245e05fbdbd6fb24");
  EXPECT_EQ(hex(md4s("abc")), "a448017aaf21d8525fc10ae87aa6729d");
  EXPECT_EQ(hex(md4s("message digest")), "d9130a8164549fe818874806e1c7014b");
}
TEST(MD4, StreamingEqualsOneShot) {
  ed2k::crypto::MD4 m;
  std::string a="mes", b="sage digest";
  m.update({reinterpret_cast<const std::byte*>(a.data()), a.size()});
  m.update({reinterpret_cast<const std::byte*>(b.data()), b.size()});
  EXPECT_EQ(hex(m.finish()), "d9130a8164549fe818874806e1c7014b");
}
