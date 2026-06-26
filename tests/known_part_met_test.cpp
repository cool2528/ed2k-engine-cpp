#include <gtest/gtest.h>
#include "ed2k/metfile/known_part_met.hpp"
using namespace ed2k;
TEST(KnownMet, RoundTrip){
  KnownFileEntry e; e.date=1700000000; e.size=9728010;
  e.hash=*FileHash::from_hex("4127a47867b6110f0f86f2d9845fb374");
  e.part_hashes={ *PartHash::from_hex("31d6cfe0d16ae931b73c59d7e0c089c0") };
  auto bytes=write_known_met(std::array<KnownFileEntry,1>{e});
  auto out=parse_known_met(bytes);
  ASSERT_TRUE(out.has_value()); ASSERT_EQ(out->size(),1u);
  EXPECT_EQ((*out)[0].hash, e.hash);
  EXPECT_EQ((*out)[0].part_hashes, e.part_hashes);
  EXPECT_EQ((*out)[0].date, e.date);
}
TEST(PartMet, RoundTrip){
  PartFileState p; p.hash=*FileHash::from_hex("31d6cfe0d16ae931b73c59d7e0c089c0");
  p.gaps={ {0,100}, {500,9728000} };
  auto bytes=write_part_met(p);
  auto out=parse_part_met(bytes);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->hash, p.hash);
  EXPECT_EQ(out->gaps, p.gaps);
}
TEST(KnownMet, RejectsBadMagic){
  std::array<std::byte,1> b{ std::byte{0x99} };
  EXPECT_FALSE(parse_known_met(b).has_value());
}
