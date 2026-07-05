#include <gtest/gtest.h>
#include "ed2k/infra/friend_list.hpp"
#include "ed2k/share/upload_queue.hpp"

using namespace ed2k;
using namespace ed2k::share;

static UserHash user_hash(std::string_view hex){
  return *UserHash::from_hex(hex);
}

static FileHash file_hash(std::string_view hex){
  return *FileHash::from_hex(hex);
}

TEST(UploadQueue, GrantsAvailableSlotAndQueuesOverflowInInsertionOrder){
  UploadQueue q(1);
  const auto file = file_hash("00112233445566778899aabbccddeeff");
  const auto p1 = user_hash("11111111111111111111111111111111");
  const auto p2 = user_hash("22222222222222222222222222222222");
  const auto p3 = user_hash("33333333333333333333333333333333");

  auto d1 = q.enqueue(p1, file);
  EXPECT_EQ(d1.state, UploadQueueState::accepted);
  EXPECT_EQ(d1.rank, 0u);

  auto d2 = q.enqueue(p2, file);
  auto d3 = q.enqueue(p3, file);
  EXPECT_EQ(d2.state, UploadQueueState::queued);
  EXPECT_EQ(d2.rank, 1u);
  EXPECT_EQ(d3.state, UploadQueueState::queued);
  EXPECT_EQ(d3.rank, 2u);
  EXPECT_TRUE(q.has_slot(p1));

  q.release(p1);
  auto grants = q.tick();
  ASSERT_EQ(grants.size(), 1u);
  EXPECT_EQ(grants[0].user_hash, p2);
  EXPECT_EQ(grants[0].file_hash, file);
  EXPECT_TRUE(q.has_slot(p2));
  EXPECT_EQ(q.rank(p3), 1u);
}

TEST(UploadQueue, DuplicatePeerKeepsExistingQueuePosition){
  UploadQueue q(1);
  const auto file = file_hash("00112233445566778899aabbccddeeff");
  const auto p1 = user_hash("11111111111111111111111111111111");
  const auto p2 = user_hash("22222222222222222222222222222222");

  EXPECT_EQ(q.enqueue(p1, file).state, UploadQueueState::accepted);
  EXPECT_EQ(q.enqueue(p2, file).rank, 1u);
  auto again = q.enqueue(p2, file);
  EXPECT_EQ(again.state, UploadQueueState::queued);
  EXPECT_EQ(again.rank, 1u);
}

TEST(UploadQueue, ReaskingFrontQueuedPeerGetsReleasedSlotWithoutBypass){
  UploadQueue q(1);
  const auto file = file_hash("00112233445566778899aabbccddeeff");
  const auto p1 = user_hash("11111111111111111111111111111111");
  const auto p2 = user_hash("22222222222222222222222222222222");
  const auto p3 = user_hash("33333333333333333333333333333333");

  EXPECT_EQ(q.enqueue(p1, file).state, UploadQueueState::accepted);
  EXPECT_EQ(q.enqueue(p2, file).rank, 1u);
  q.release(p1);

  auto bypass = q.enqueue(p3, file);
  EXPECT_EQ(bypass.state, UploadQueueState::queued);
  EXPECT_EQ(bypass.rank, 2u);

  auto front = q.enqueue(p2, file);
  EXPECT_EQ(front.state, UploadQueueState::accepted);
  EXPECT_EQ(front.rank, 0u);
  EXPECT_TRUE(q.has_slot(p2));
  EXPECT_EQ(q.rank(p3), 1u);
}

TEST(UploadQueue, FriendSlotTakesPriorityOverQueuedNonFriends){
  infra::FriendList friends;
  const auto file = file_hash("00112233445566778899aabbccddeeff");
  const auto active = user_hash("11111111111111111111111111111111");
  const auto regular = user_hash("22222222222222222222222222222222");
  const auto friend_peer = user_hash("33333333333333333333333333333333");
  friends.add({friend_peer, std::nullopt, "friend", true});

  UploadQueue q(1, nullptr, &friends);
  EXPECT_EQ(q.enqueue(active, file).state, UploadQueueState::accepted);
  EXPECT_EQ(q.enqueue(regular, file).rank, 1u);

  auto fd = q.enqueue(friend_peer, file);
  EXPECT_EQ(fd.state, UploadQueueState::queued);
  EXPECT_EQ(fd.rank, 1u);
  EXPECT_EQ(q.rank(regular), 2u);

  q.release(active);
  auto grants = q.tick();
  ASSERT_EQ(grants.size(), 1u);
  EXPECT_EQ(grants[0].user_hash, friend_peer);
}
