#include <gtest/gtest.h>

#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

#include "ed2k/crypto/rc4.hpp"

namespace {
std::vector<std::byte> bytes(std::string_view text) {
  return {reinterpret_cast<const std::byte*>(text.data()),
          reinterpret_cast<const std::byte*>(text.data()) + text.size()};
}

std::vector<std::byte> hex_bytes(std::string_view hex) {
  auto nybble = [](char c) -> unsigned {
    return c <= '9' ? static_cast<unsigned>(c - '0')
                    : static_cast<unsigned>((c | 0x20) - 'a' + 10);
  };

  std::vector<std::byte> out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(std::byte((nybble(hex[i]) << 4) | nybble(hex[i + 1])));
  }
  return out;
}
} // namespace

TEST(RC4, EncryptsKnownVector) {
  auto input = bytes("Plaintext");
  ed2k::crypto::RC4 rc4(bytes("Key"));

  rc4.process(input);

  EXPECT_EQ(input, hex_bytes("bbf316e8d940af0ad3"));
}

TEST(RC4, KeystreamContinuesAcrossProcessCalls) {
  auto one_shot = bytes("Plaintext");
  ed2k::crypto::RC4 rc4_one_shot(bytes("Key"));
  rc4_one_shot.process(one_shot);

  auto split_a = bytes("Plain");
  auto split_b = bytes("text");
  ed2k::crypto::RC4 rc4_split(bytes("Key"));
  rc4_split.process(split_a);
  rc4_split.process(split_b);

  split_a.insert(split_a.end(), split_b.begin(), split_b.end());
  EXPECT_EQ(split_a, one_shot);
}

TEST(RC4, ProcessByteMatchesBufferedProcess) {
  auto buffered = bytes("Plaintext");
  ed2k::crypto::RC4 rc4_buffered(bytes("Key"));
  rc4_buffered.process(buffered);

  auto input = bytes("Plaintext");
  std::vector<std::byte> bytewise;
  bytewise.reserve(input.size());
  ed2k::crypto::RC4 rc4_bytewise(bytes("Key"));
  for (auto value : input) {
    bytewise.push_back(rc4_bytewise.process_byte(value));
  }

  EXPECT_EQ(bytewise, buffered);
}

TEST(RC4, DiscardSkipsKeystreamBytes) {
  std::vector<std::byte> full(9, std::byte{0x00});
  ed2k::crypto::RC4 rc4_full(bytes("Key"));
  rc4_full.process(full);

  std::vector<std::byte> tail(4, std::byte{0x00});
  ed2k::crypto::RC4 rc4_tail(bytes("Key"));
  rc4_tail.discard(5);
  rc4_tail.process(tail);

  EXPECT_EQ(tail, std::vector<std::byte>(full.begin() + 5, full.end()));
}
