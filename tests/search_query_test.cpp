#include <gtest/gtest.h>
#include "ed2k/server/search_query.hpp"
using namespace ed2k::server;
static std::vector<std::byte> bytes(std::initializer_list<int> xs){
  std::vector<std::byte> v; for(int x:xs) v.push_back(std::byte(x)); return v;
}
TEST(SearchQuery, KeywordLeaf){
  SearchExpr k = Keyword{"foo"};
  EXPECT_EQ(serialize_search(k), bytes({0x01, 0x03,0x00, 'f','o','o'}));  // 0x01 + u16(3) + "foo"
}
TEST(SearchQuery, TypeIsLeaf){
  SearchExpr t = TypeIs{FileType::Audio};
  EXPECT_EQ(serialize_search(t), bytes({0x02, 0x05,0x00,'A','u','d','i','o', 0x01,0x00, tag::FT_FILETYPE}));
}
TEST(SearchQuery, ExtensionIsLeaf){
  SearchExpr e = ExtensionIs{"mp3"};
  EXPECT_EQ(serialize_search(e), bytes({0x02, 0x03,0x00,'m','p','3', 0x01,0x00, tag::FT_FILEFORMAT}));
}
TEST(SearchQuery, SizeAtLeastLeaf){
  SearchExpr s = SizeAtLeast{100};
  // 0x03 + u32(100) + GREATER(1) + u16(1) + FT_FILESIZE(0x02)
  EXPECT_EQ(serialize_search(s), bytes({0x03, 100,0,0,0, searchop::GREATER, 0x01,0x00, tag::FT_FILESIZE}));
}
TEST(SearchQuery, SizeAtMostLeaf){
  SearchExpr s = SizeAtMost{200};
  EXPECT_EQ(serialize_search(s), bytes({0x03, 200,0,0,0, searchop::LESS, 0x01,0x00, tag::FT_FILESIZE}));
}
TEST(SearchQuery, AvailAtLeastLeaf){
  SearchExpr s = AvailAtLeast{5};
  EXPECT_EQ(serialize_search(s), bytes({0x03, 5,0,0,0, searchop::GREATER, 0x01,0x00, tag::FT_SOURCES}));
}
TEST(SearchQuery, AndTree){
  SearchExpr e = Keyword{"a"} & Keyword{"b"};
  // 0x00 AND(0x00) + [0x01 01 00 'a'] + [0x01 01 00 'b']
  EXPECT_EQ(serialize_search(e), bytes({0x00,0x00, 0x01,0x01,0x00,'a', 0x01,0x01,0x00,'b'}));
}
TEST(SearchQuery, OrTree){
  SearchExpr e = Keyword{"a"} | Keyword{"b"};
  EXPECT_EQ(serialize_search(e), bytes({0x00,0x01, 0x01,0x01,0x00,'a', 0x01,0x01,0x00,'b'}));
}
TEST(SearchQuery, AndNotTree){
  SearchExpr e = and_not(Keyword{"a"}, Keyword{"b"});
  EXPECT_EQ(serialize_search(e), bytes({0x00,0x02, 0x01,0x01,0x00,'a', 0x01,0x01,0x00,'b'}));
}
TEST(SearchQuery, NestedTree){
  // (a AND b) OR c
  SearchExpr e = (Keyword{"a"} & Keyword{"b"}) | Keyword{"c"};
  EXPECT_EQ(serialize_search(e),
    bytes({0x00,0x01,                              // OR
           0x00,0x00, 0x01,0x01,0x00,'a', 0x01,0x01,0x00,'b',  // AND(a,b)
           0x01,0x01,0x00,'c'}));                  // keyword c
}
TEST(SearchQuery, ParseSingleKeyword){
  // 单 token: 与直接构造 Keyword 序列化一致
  EXPECT_EQ(serialize_search(parse_keyword_query("windows")),
            serialize_search(SearchExpr(Keyword{"windows"})));
}
TEST(SearchQuery, ParseSpaceSeparatedAnds){
  // "windows 10" -> Keyword(windows) AND Keyword(10)
  EXPECT_EQ(serialize_search(parse_keyword_query("windows 10")),
            bytes({0x00,0x00, 0x01,0x07,0x00,'w','i','n','d','o','w','s', 0x01,0x02,0x00,'1','0'}));
}
TEST(SearchQuery, ParseUnderscoreSeparated){
  // 下划线同样是分隔符: "windows_10" 与 "windows 10" 等价
  EXPECT_EQ(serialize_search(parse_keyword_query("windows_10")),
            serialize_search(parse_keyword_query("windows 10")));
}
TEST(SearchQuery, ParseCollapsesConsecutiveDelims){
  // 连续/首尾分隔符不产生空 token
  EXPECT_EQ(serialize_search(parse_keyword_query("  a . b  ")),
            bytes({0x00,0x00, 0x01,0x01,0x00,'a', 0x01,0x01,0x00,'b'}));
}
TEST(SearchQuery, ParseAllDelimsFallsBackToWholeString){
  // 全是分隔符(无有效 token): 回退为整串单 Keyword, 不抛异常/不产生空表达式
  EXPECT_EQ(serialize_search(parse_keyword_query("___")),
            serialize_search(SearchExpr(Keyword{"___"})));
}
