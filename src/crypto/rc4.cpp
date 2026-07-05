#include "ed2k/crypto/rc4.hpp"

#include <algorithm>

namespace ed2k::crypto {

RC4::RC4(std::span<const std::byte> key) {
  for (std::size_t n = 0; n < state_.size(); ++n) {
    state_[n] = static_cast<std::uint8_t>(n);
  }
  if (key.empty()) {
    return;
  }

  std::uint8_t j = 0;
  for (std::size_t n = 0; n < state_.size(); ++n) {
    j = static_cast<std::uint8_t>(j + state_[n] + std::to_integer<std::uint8_t>(key[n % key.size()]));
    std::swap(state_[n], state_[j]);
  }
}

void RC4::process(std::span<std::byte> data) {
  for (auto& value : data) {
    value = process_byte(value);
  }
}

std::byte RC4::process_byte(std::byte value) {
  return std::byte(std::to_integer<std::uint8_t>(value) ^ next());
}

void RC4::discard(std::size_t count) {
  for (std::size_t n = 0; n < count; ++n) {
    (void)next();
  }
}

std::uint8_t RC4::next() {
  i_ = static_cast<std::uint8_t>(i_ + 1u);
  j_ = static_cast<std::uint8_t>(j_ + state_[i_]);
  std::swap(state_[i_], state_[j_]);
  return state_[static_cast<std::uint8_t>(state_[i_] + state_[j_])];
}

} // namespace ed2k::crypto
