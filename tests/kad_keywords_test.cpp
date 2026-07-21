#include <gtest/gtest.h>
#include <algorithm>

#include <string>
#include <vector>

#include "ed2k/kad/keywords.hpp"

using namespace ed2k::kad;

TEST(KadKeywords, SplitsFilenameLikeAmuleSearchManager) {
  EXPECT_EQ(keywords_for_name("Ubuntu-22.04_x64.iso [Final]"),
            (std::vector<std::string>{"ubuntu", "x64", "iso", "final"}));
}

TEST(KadKeywords, RemovesDuplicatesByLatestPosition) {
  EXPECT_EQ(keywords_for_name("alpha beta alpha"),
            (std::vector<std::string>{"beta", "alpha"}));
}

TEST(KadKeywords, KeywordIdUsesLowercaseUtf8Bytes) {
  EXPECT_EQ(keyword_id("Ubuntu"), keyword_id("ubuntu"));
  EXPECT_NE(keyword_id("ubuntu"), keyword_id("debian"));
}

TEST(KadKeywords, BuildQuerySingleWordHasNoFilters) {
  // 单词: target = 该词 keyword_id, 无过滤词
  auto q = build_keyword_query("windows");
  ASSERT_TRUE(q.valid);
  EXPECT_EQ(q.target, keyword_id("windows"));
  EXPECT_TRUE(q.filters.empty());
}

TEST(KadKeywords, BuildQueryPicksLongestWordAsTarget) {
  // "windows 1909": 最长词 windows(7)>1909(4) 做 target, 1909 入 filters
  auto q = build_keyword_query("windows 1909");
  ASSERT_TRUE(q.valid);
  EXPECT_EQ(q.target, keyword_id("windows"));
  EXPECT_EQ(q.filters, (std::vector<std::string>{"1909"}));
}

TEST(KadKeywords, BuildQueryUnderscoresAndShortWordsDropped) {
  // 下划线分词; <3 字符词(cn/10)被丢弃; 最长词 consumer/editions(8) 做 target
  auto q = build_keyword_query("cn_windows_10_consumer_editions_1909");
  ASSERT_TRUE(q.valid);
  // consumer 在 editions 之前(去重后按出现顺序), 两者等长, longest 取先出现的 consumer
  EXPECT_EQ(q.target, keyword_id("consumer"));
  // filters 含除定位词外的其余有效词(不含 cn/10)
  EXPECT_NE(std::find(q.filters.begin(), q.filters.end(), "windows"), q.filters.end());
  EXPECT_NE(std::find(q.filters.begin(), q.filters.end(), "1909"), q.filters.end());
  EXPECT_NE(std::find(q.filters.begin(), q.filters.end(), "editions"), q.filters.end());
  EXPECT_EQ(std::find(q.filters.begin(), q.filters.end(), "cn"), q.filters.end());
  EXPECT_EQ(std::find(q.filters.begin(), q.filters.end(), "10"), q.filters.end());
}

TEST(KadKeywords, BuildQueryAllShortWordsInvalid) {
  // 全部 <3 字符: 无有效词, valid=false, 调用方回退整串
  auto q = build_keyword_query("a b 10");
  EXPECT_FALSE(q.valid);
}

TEST(KadKeywords, NameContainsAllCaseInsensitiveSubstring) {
  EXPECT_TRUE(name_contains_all("cn_windows_10_consumer_editions_1909_x64.iso",
                                {"1909", "editions"}));
  EXPECT_FALSE(name_contains_all("cn_windows_10_consumer_editions_1909_x64.iso",
                                 {"1909", "server"}));
  EXPECT_TRUE(name_contains_all("anything", {}));  // 空 filters 恒真
}
