#include <array>
#include <chrono>
#include <optional>

#include <gtest/gtest.h>

#include "ed2k/infra/client_list.hpp"
#include "ed2k/infra/friend_list.hpp"
#include "ed2k/share/known_file.hpp"

using namespace ed2k;
using namespace std::chrono_literals;

namespace {
UserHash user_hash(std::string_view hex) {
  return *UserHash::from_hex(hex);
}

FileHash file_hash(std::string_view hex) {
  return *FileHash::from_hex(hex);
}
} // namespace

TEST(FriendList, RoundTripPreservesFriends) {
  infra::Friend alice;
  alice.user_hash = user_hash("11111111111111111111111111111111");
  alice.kad_id = *kad::KadID::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  alice.name = "alice";
  alice.friend_slot = true;

  infra::Friend bob;
  bob.user_hash = user_hash("22222222222222222222222222222222");
  bob.name = "bob";
  bob.friend_slot = false;

  auto bytes = infra::write_friends(std::array<infra::Friend, 2>{alice, bob});
  auto parsed = infra::parse_friends(bytes);

  ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
  ASSERT_EQ(parsed->size(), 2u);
  EXPECT_EQ((*parsed)[0], alice);
  EXPECT_EQ((*parsed)[1], bob);
}

TEST(FriendList, FindsByUserHash) {
  infra::FriendList friends;
  const auto alice = user_hash("11111111111111111111111111111111");
  friends.add({alice, std::nullopt, "alice", true});

  EXPECT_TRUE(friends.contains(alice));
  EXPECT_EQ(friends.find(alice)->name, "alice");
  EXPECT_FALSE(friends.contains(user_hash("33333333333333333333333333333333")));
}

TEST(ClientList, UpdatesExistingClientAndCleansStaleEntries) {
  infra::ClientList clients(30min);
  const auto now = std::chrono::system_clock::time_point{10h};
  const auto old_peer = user_hash("11111111111111111111111111111111");
  const auto fresh_peer = user_hash("22222222222222222222222222222222");

  clients.upsert(old_peer, *IPv4::from_dotted("10.0.0.1"), 4662, now - 31min);
  clients.upsert(fresh_peer, *IPv4::from_dotted("10.0.0.2"), 4663, now - 5min);
  clients.upsert(fresh_peer, *IPv4::from_dotted("10.0.0.3"), 4664, now - 1min);

  auto removed = clients.cleanup(now);

  ASSERT_EQ(removed.size(), 1u);
  EXPECT_EQ(removed[0].user_hash, old_peer);
  EXPECT_EQ(clients.find(old_peer), nullptr);
  const auto* fresh = clients.find(fresh_peer);
  ASSERT_NE(fresh, nullptr);
  EXPECT_EQ(fresh->ip, *IPv4::from_dotted("10.0.0.3"));
  EXPECT_EQ(fresh->port, 4664);
}

TEST(ClientList, ConvertsTrackedClientToSourceExchangeSource) {
  infra::ClientList clients;
  const auto peer = user_hash("11111111111111111111111111111111");
  clients.upsert(peer, *IPv4::from_dotted("1.2.3.4"), 4662, std::chrono::system_clock::now());

  auto source = clients.source_for(peer);

  ASSERT_TRUE(source.has_value());
  EXPECT_EQ(source->client_id, IPv4::from_host(0x01020304).host());
  EXPECT_EQ(source->port, 4662);
  EXPECT_EQ(source->user_hash, peer);
}

TEST(ClientList, AttachesTrackedClientToKnownFileSources) {
  infra::ClientList clients;
  const auto peer = user_hash("11111111111111111111111111111111");
  const auto file = file_hash("00112233445566778899aabbccddeeff");
  clients.upsert(peer, *IPv4::from_dotted("1.2.3.4"), 4662, std::chrono::system_clock::now());

  share::KnownFile known;
  known.hash = file;
  share::KnownFileDB db;
  db.add(known);

  EXPECT_TRUE(clients.attach_source(db, file, peer));
  const auto* stored = db.find(file);
  ASSERT_NE(stored, nullptr);
  ASSERT_EQ(stored->sources.size(), 1u);
  EXPECT_EQ(stored->sources[0].user_hash, peer);
  EXPECT_EQ(stored->sources[0].port, 4662);
}
