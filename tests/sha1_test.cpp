#include <gtest/gtest.h>
#include <string>
#include "crypto/sha1.hpp"
static std::string hex20(std::array<std::byte,20> h){
  static const char* k="0123456789abcdef"; std::string s;
  for(auto b:h){auto v=std::to_integer<unsigned>(b); s+=k[v>>4]; s+=k[v&15];}
  return s;
}
static std::array<std::byte,20> sha(std::string_view in){
  return ed2k::crypto::sha1({reinterpret_cast<const std::byte*>(in.data()), in.size()});
}
TEST(SHA1, Fips180Vectors){
  EXPECT_EQ(hex20(sha("")),    "da39a3ee5e6b4b0d3255bfef95601890afd80709");
  EXPECT_EQ(hex20(sha("abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
  EXPECT_EQ(hex20(sha("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}
