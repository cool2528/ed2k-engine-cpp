#pragma once
#include <cstdint>
#include <span>
#include <system_error>
#include <unordered_map>
#include <vector>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"

namespace ed2k::share {

struct CreditRecord {
  UserHash key;
  std::uint64_t uploaded = 0;
  std::uint64_t downloaded = 0;
  auto operator<=>(const CreditRecord&) const = default;
};

std::vector<std::byte> write_client_credits(std::span<const CreditRecord> records);
tl::expected<std::vector<CreditRecord>, std::error_code>
  parse_client_credits(std::span<const std::byte> data);

class ClientCredits {
 public:
  void add_uploaded(const UserHash& key, std::uint64_t bytes);
  void add_downloaded(const UserHash& key, std::uint64_t bytes);
  std::uint64_t uploaded(const UserHash& key) const;
  std::uint64_t downloaded(const UserHash& key) const;
  std::int64_t score(const UserHash& key) const;
  const std::vector<CreditRecord>& records() const noexcept { return records_; }

 private:
  CreditRecord& ensure(const UserHash& key);
  const CreditRecord* find(const UserHash& key) const;

  std::vector<CreditRecord> records_;
  std::unordered_map<UserHash, std::size_t> by_key_;
};

} // namespace ed2k::share
