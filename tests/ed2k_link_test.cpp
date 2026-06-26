#include <gtest/gtest.h>
#include "ed2k/link/ed2k_link.hpp"
using namespace ed2k;
TEST(Link, ParseFileLink){
  auto r=parse_link("ed2k://|file|test.bin|12345|31d6cfe0d16ae931b73c59d7e0c089c0|/");
  ASSERT_TRUE(r.has_value());
  auto* f=std::get_if<Ed2kFileLink>(&*r); ASSERT_NE(f,nullptr);
  EXPECT_EQ(f->name,"test.bin"); EXPECT_EQ(f->size,12345u);
  EXPECT_EQ(f->hash.to_hex(),"31d6cfe0d16ae931b73c59d7e0c089c0");
}
TEST(Link, FileLinkRoundTrip){
  Ed2kFileLink f; f.name="a b.dat"; f.size=9728000;
  f.hash=*FileHash::from_hex("4127a47867b6110f0f86f2d9845fb374");
  auto s=to_string(f);
  auto r=parse_link(s); ASSERT_TRUE(r.has_value());
  auto* g=std::get_if<Ed2kFileLink>(&*r); ASSERT_NE(g,nullptr);
  EXPECT_EQ(g->name,f.name); EXPECT_EQ(g->size,f.size); EXPECT_EQ(g->hash,f.hash);
}
TEST(Link, ParseServerLink){
  auto r=parse_link("ed2k://|server|192.168.0.1|4661|/");
  ASSERT_TRUE(r.has_value());
  auto* s=std::get_if<ServerLink>(&*r); ASSERT_NE(s,nullptr);
  EXPECT_EQ(s->ip.to_dotted(),"192.168.0.1"); EXPECT_EQ(s->port,4661);
}
TEST(Link, RejectsMalformed){
  EXPECT_FALSE(parse_link("http://x").has_value());
  EXPECT_FALSE(parse_link("ed2k://|file|onlyname|/").has_value());
}
