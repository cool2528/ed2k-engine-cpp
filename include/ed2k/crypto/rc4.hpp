#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace ed2k::crypto {

class RC4 {
 public:
  explicit RC4(std::span<const std::byte> key);

  void process(std::span<std::byte> data);
  std::byte process_byte(std::byte value);
  void discard(std::size_t count);

 private:
  std::uint8_t next();

  std::array<std::uint8_t, 256> state_{};
  std::uint8_t i_ = 0;
  std::uint8_t j_ = 0;
};

} // namespace ed2k::crypto
