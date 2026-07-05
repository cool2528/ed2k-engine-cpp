#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <span>
#include <string_view>

#include "ed2k/crypto/md5.hpp"

namespace {
std::string hex(std::span<const std::byte, 16> digest) {
  static constexpr char k_hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(32);
  for (auto value : digest) {
    const auto byte = std::to_integer<unsigned>(value);
    out.push_back(k_hex[byte >> 4]);
    out.push_back(k_hex[byte & 0x0f]);
  }
  return out;
}

std::span<const std::byte> bytes(std::string_view text) {
  return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}
} // namespace

TEST(MD5, Rfc1321Vectors) {
  EXPECT_EQ(hex(ed2k::crypto::md5(bytes(""))), "d41d8cd98f00b204e9800998ecf8427e");
  EXPECT_EQ(hex(ed2k::crypto::md5(bytes("abc"))), "900150983cd24fb0d6963f7d28e17f72");
  EXPECT_EQ(hex(ed2k::crypto::md5(bytes("message digest"))), "f96b697d7cb7938d525a2f31aaf161d0");
}
