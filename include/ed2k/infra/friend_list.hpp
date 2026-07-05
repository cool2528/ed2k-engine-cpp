#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

#include <tl/expected.hpp>

#include "ed2k/core/hash.hpp"
#include "ed2k/kad/kad_id.hpp"

namespace ed2k::infra {

struct Friend {
  UserHash user_hash;
  std::optional<kad::KadID> kad_id;
  std::string name;
  bool friend_slot = true;

  bool operator==(const Friend&) const = default;
};

std::vector<std::byte> write_friends(std::span<const Friend> friends);
tl::expected<std::vector<Friend>, std::error_code>
parse_friends(std::span<const std::byte> data);

class FriendList {
 public:
  void add(Friend friend_entry);
  bool contains(const UserHash& user_hash) const;
  bool is_friend_slot(const UserHash& user_hash) const;
  const Friend* find(const UserHash& user_hash) const;
  const std::vector<Friend>& friends() const noexcept { return friends_; }

 private:
  std::vector<Friend> friends_;
  std::unordered_map<UserHash, std::size_t> by_hash_;
};

} // namespace ed2k::infra
