#include <gtest/gtest.h>

#include "ed2k/infra/chat_relay.hpp"
#include "ed2k/infra/friend_list.hpp"
#include "ed2k/infra/scheduler.hpp"

using namespace ed2k;
using namespace ed2k::infra;

namespace {
UserHash user_hash(std::string_view hex) {
  return *UserHash::from_hex(hex);
}
} // namespace

TEST(Scheduler, ParsesRuleAndReturnsLimitsInsideWindow) {
  auto rule = SchedulerRule::parse("daily 08:00-18:00 upload=1024 download=2048");
  ASSERT_TRUE(rule.has_value()) << rule.error().message();

  Scheduler scheduler;
  scheduler.add(*rule);

  auto active = scheduler.limits_at(2, 9 * 60);
  ASSERT_TRUE(active.has_value());
  EXPECT_EQ(active->upload_limit_bps, 1024u);
  EXPECT_EQ(active->download_limit_bps, 2048u);
  EXPECT_FALSE(scheduler.limits_at(2, 19 * 60).has_value());
}

TEST(Scheduler, RejectsMalformedRuleWithoutThrowing) {
  auto rule = SchedulerRule::parse("daily bad upload=x");
  EXPECT_FALSE(rule.has_value());
}

TEST(ChatRelay, DispatchesIncomingMessageAndMarksFriends) {
  FriendList friends;
  const auto alice = user_hash("11111111111111111111111111111111");
  friends.add({alice, std::nullopt, "alice", true});

  ChatRelay relay(&friends);
  bool called = false;
  ChatMessage delivered;
  relay.on_message = [&](ChatMessage message) {
    called = true;
    delivered = std::move(message);
  };

  auto payload = encode_chat_message("hello");
  auto result = relay.on_incoming(alice, payload);

  ASSERT_TRUE(result.has_value()) << result.error().message();
  EXPECT_TRUE(called);
  EXPECT_EQ(delivered.sender, alice);
  EXPECT_EQ(delivered.text, "hello");
  EXPECT_TRUE(delivered.from_friend);
}
