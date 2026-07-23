#include <gtest/gtest.h>
#include <string>
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

// 排队人数应可查询：占满槽位后新请求进入等待队列
TEST(UploadQueue, QueuedSizeReflectsWaitingPeers){
  UploadQueue q(1);
  const auto file = file_hash("00112233445566778899aabbccddeeff");
  const auto p1 = user_hash("11111111111111111111111111111111");
  const auto p2 = user_hash("22222222222222222222222222222222");

  EXPECT_EQ(q.enqueue(p1, file).state, UploadQueueState::accepted);
  EXPECT_EQ(q.enqueue(p2, file).state, UploadQueueState::queued);
  EXPECT_EQ(q.queued_size(), 1u);
  q.remove(p2);
  EXPECT_EQ(q.queued_size(), 0u);
}

// P2c A7: 排队队列已达 max_queued 容量上限时, 新的(此前从未出现过的)请求方应得到 full 而非
// 无限制地追加到 queued_ 尾巴——调用方据此答 QUEUEFULL 而不是给一个不断增长、永远排不到的名次。
TEST(UploadQueue, QueueFullWhenQueuedLengthReachesCapacity){
  UploadQueue q(1, nullptr, nullptr, /*max_queued=*/1);
  const auto file = file_hash("00112233445566778899aabbccddeeff");
  const auto p1 = user_hash("11111111111111111111111111111111");
  const auto p2 = user_hash("22222222222222222222222222222222");
  const auto p3 = user_hash("33333333333333333333333333333333");

  EXPECT_EQ(q.enqueue(p1, file).state, UploadQueueState::accepted);   // 占满唯一槽位
  EXPECT_EQ(q.enqueue(p2, file).state, UploadQueueState::queued);     // 排队队列恰好占满 1 个名额
  auto full = q.enqueue(p3, file);                                    // 队列已达容量上限
  EXPECT_EQ(full.state, UploadQueueState::full);
  EXPECT_EQ(q.queued_size(), 1u);   // p3 未被插入 queued_
  EXPECT_FALSE(q.has_slot(p3));
}

// 默认构造(不传 max_queued)必须保持不限队列长度的旧行为——防止本次改动回归既有调用方。
TEST(UploadQueue, DefaultConstructedQueueHasUnboundedQueueLength){
  UploadQueue q(1);
  const auto file = file_hash("00112233445566778899aabbccddeeff");
  EXPECT_EQ(q.enqueue(user_hash("11111111111111111111111111111111"), file).state, UploadQueueState::accepted);
  static constexpr char kHexDigits[] = "0123456789abcdef";
  for(int i = 2; i < 50; ++i){
    std::string hex(32, '0');
    hex[0] = kHexDigits[(i / 16) % 16];
    hex[1] = kHexDigits[i % 16];
    EXPECT_EQ(q.enqueue(user_hash(hex), file).state, UploadQueueState::queued);
  }
  EXPECT_EQ(q.queued_size(), 48u);
}

// P2c A8: find_queued 按 (ip, file_hash) 反查排队中记录的 user_hash——UDP REASKFILEPING 应答的
// 核心查表(载荷只有文件 hash, 身份靠数据报来源 IP 匹配 enqueue() 时记录的 ip)。
TEST(UploadQueue, FindQueuedMatchesByIpAndFileHash){
  UploadQueue q(1);
  const auto file = file_hash("00112233445566778899aabbccddeeff");
  const auto other_file = file_hash("ffeeddccbbaa99887766554433221100");
  const auto p1 = user_hash("11111111111111111111111111111111");
  const auto p2 = user_hash("22222222222222222222222222222222");
  const auto ip1 = *IPv4::from_dotted("127.0.0.1");
  const auto ip2 = *IPv4::from_dotted("127.0.0.2");

  EXPECT_EQ(q.enqueue(p1, file, ip1).state, UploadQueueState::accepted);   // 占满槽位(active, 非 queued_)
  EXPECT_EQ(q.enqueue(p2, file, ip2).state, UploadQueueState::queued);

  auto found = q.find_queued(ip2, file);
  ASSERT_TRUE(found.has_value());
  EXPECT_EQ(*found, p2);

  EXPECT_FALSE(q.find_queued(ip1, file).has_value());          // p1 在 active_ 不在 queued_, 查不到
  EXPECT_FALSE(q.find_queued(ip2, other_file).has_value());     // 同 ip 不同文件不匹配
  EXPECT_FALSE(q.find_queued(*IPv4::from_dotted("127.0.0.3"), file).has_value());   // 未知 ip
}
