#include <gtest/gtest.h>
#include <array>
#include "ed2k/share/client_credits.hpp"
#include "ed2k/share/upload_queue.hpp"

using namespace ed2k;
using namespace ed2k::share;

static UserHash user_hash(std::string_view hex){
  return *UserHash::from_hex(hex);
}

TEST(ClientCredits, RoundTripPreservesAccounting){
  ClientCredits credits;
  const auto peer = user_hash("11111111111111111111111111111111");
  credits.add_uploaded(peer, 1200);
  credits.add_downloaded(peer, 300);

  auto data = write_client_credits(credits.records());
  auto parsed = parse_client_credits(data);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->size(), 1u);
  EXPECT_EQ((*parsed)[0].key, peer);
  EXPECT_EQ((*parsed)[0].uploaded, 1200u);
  EXPECT_EQ((*parsed)[0].downloaded, 300u);
}

TEST(ClientCredits, ScoreReflectsUploadedMinusDownloaded){
  ClientCredits credits;
  const auto peer = user_hash("11111111111111111111111111111111");
  const auto base = credits.score(peer);
  credits.add_uploaded(peer, 4096);
  EXPECT_GT(credits.score(peer), base);
  credits.add_downloaded(peer, 8192);
  EXPECT_LT(credits.score(peer), base);
}

TEST(ClientCredits, UploadQueueUsesCreditScoreForQueuedOrder){
  ClientCredits credits;
  const auto file = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  const auto active = user_hash("11111111111111111111111111111111");
  const auto low = user_hash("22222222222222222222222222222222");
  const auto high = user_hash("33333333333333333333333333333333");
  credits.add_uploaded(high, 10000);

  UploadQueue q(1, &credits);
  EXPECT_EQ(q.enqueue(active, file).state, UploadQueueState::accepted);
  EXPECT_EQ(q.enqueue(low, file).rank, 1u);
  EXPECT_EQ(q.enqueue(high, file).rank, 1u);
  EXPECT_EQ(q.rank(low), 2u);

  q.release(active);
  auto front = q.enqueue(high, file);
  EXPECT_EQ(front.state, UploadQueueState::accepted);
  EXPECT_TRUE(q.has_slot(high));
}
