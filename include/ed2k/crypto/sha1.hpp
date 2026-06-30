#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <vector>
#include "ed2k/core/hash.hpp"
namespace ed2k::crypto {

class SHA1 {
 public:
  SHA1() noexcept { reset(); }
  void reset() noexcept;
  void update(std::span<const std::byte> data) noexcept;
  std::array<std::byte, 20> finish() noexcept;

  // Access the finished hash bytes
  const std::array<std::byte, 20>& bytes() const noexcept { return bytes_; }
  bool operator==(const SHA1& other) const noexcept { return bytes_ == other.bytes_; }

 private:
  void transform(const std::uint8_t b[64]) noexcept;
  std::uint32_t state_[5];
  std::uint64_t bitlen_;
  std::uint8_t buflen_;
  std::uint8_t buf_[64];
  std::array<std::byte, 20> bytes_;
};

std::array<std::byte, 20> sha1(std::span<const std::byte> d) noexcept;

}
