#include <gtest/gtest.h>

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
