#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <cstddef>
namespace ed2k::crypto {
class MD4 {
 public:
  MD4() noexcept { reset(); }
  void reset() noexcept;
  void update(std::span<const std::byte> data) noexcept;
  std::array<std::byte,16> finish() noexcept;
 private:
  void transform(const std::uint8_t block[64]) noexcept;
  std::uint32_t state_[4];
  std::uint64_t bitlen_;
  std::uint8_t  buf_[64];
  std::size_t   buflen_;
};
std::array<std::byte,16> md4(std::span<const std::byte> data) noexcept;
}
