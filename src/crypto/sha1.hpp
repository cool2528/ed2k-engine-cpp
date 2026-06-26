#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <cstddef>
namespace ed2k::crypto {
class SHA1 {
 public:
  SHA1() noexcept { reset(); }
  void reset() noexcept;
  void update(std::span<const std::byte>) noexcept;
  std::array<std::byte,20> finish() noexcept;
 private:
  void transform(const std::uint8_t block[64]) noexcept;
  std::uint32_t state_[5];
  std::uint64_t bitlen_;
  std::uint8_t  buf_[64];
  std::size_t   buflen_;
};
std::array<std::byte,20> sha1(std::span<const std::byte>) noexcept;
}
