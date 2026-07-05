#include "ed2k/infra/friend_list.hpp"

#include <algorithm>
#include <array>

#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::infra {
namespace {
constexpr std::uint32_t friend_magic = 0x52463245; // E2FR
constexpr std::uint16_t friend_version = 1;
} // namespace

std::vector<std::byte> write_friends(std::span<const Friend> friends) {
  codec::ByteWriter w;
  w.u32(friend_magic);
  w.u16(friend_version);
  w.u32(static_cast<std::uint32_t>(friends.size()));
  for (const auto& friend_entry : friends) {
    w.hash16(friend_entry.user_hash);
    w.u8(friend_entry.kad_id.has_value() ? 1u : 0u);
    if (friend_entry.kad_id) {
      w.blob(friend_entry.kad_id->bytes());
    }
    w.string16(friend_entry.name);
    w.u8(friend_entry.friend_slot ? 1u : 0u);
  }
  return w.take();
}

tl::expected<std::vector<Friend>, std::error_code>
parse_friends(std::span<const std::byte> data) {
  codec::ByteReader r(data);
  const auto magic = r.u32();
  const auto version = r.u16();
  const auto count = r.u32();
  if (!r.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (magic != friend_magic) {
    return tl::unexpected(make_error_code(errc::bad_magic));
  }
  if (version != friend_version) {
    return tl::unexpected(make_error_code(errc::unsupported_version));
  }
  if (count > 100000) {
    return tl::unexpected(make_error_code(errc::count_too_large));
  }

  std::vector<Friend> out;
  out.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    Friend friend_entry;
    friend_entry.user_hash = r.hash16();
    const auto has_kad = r.u8() != 0;
    if (has_kad) {
      auto bytes = r.blob(kad::KadID::size);
      std::array<std::byte, kad::KadID::size> id{};
      std::copy(bytes.begin(), bytes.end(), id.begin());
      friend_entry.kad_id = kad::KadID::from_bytes(id);
    }
    friend_entry.name = r.string16();
    friend_entry.friend_slot = r.u8() != 0;
    if (!r.ok()) {
      return tl::unexpected(make_error_code(errc::buffer_underflow));
    }
    out.push_back(std::move(friend_entry));
  }
  return out;
}

void FriendList::add(Friend friend_entry) {
  auto [it, inserted] = by_hash_.emplace(friend_entry.user_hash, friends_.size());
  if (inserted) {
    friends_.push_back(std::move(friend_entry));
  } else {
    friends_[it->second] = std::move(friend_entry);
  }
}

bool FriendList::contains(const UserHash& user_hash) const {
  return by_hash_.contains(user_hash);
}

bool FriendList::is_friend_slot(const UserHash& user_hash) const {
  const auto* friend_entry = find(user_hash);
  return friend_entry && friend_entry->friend_slot;
}

const Friend* FriendList::find(const UserHash& user_hash) const {
  auto it = by_hash_.find(user_hash);
  if (it == by_hash_.end()) {
    return nullptr;
  }
  return &friends_[it->second];
}

} // namespace ed2k::infra
