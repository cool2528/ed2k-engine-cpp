#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "ed2k/infra/preferences.hpp"
#include "ed2k/util/error.hpp"

using ed2k::infra::Preferences;

namespace {
std::filesystem::path temp_path(const char* name) {
  return std::filesystem::temp_directory_path() / name;
}
} // namespace

TEST(Preferences, DefaultsMatchEngineConventions) {
  const auto prefs = Preferences::defaults();

  EXPECT_EQ(prefs.tcp_port, 4662);
  EXPECT_EQ(prefs.udp_port, 4672);
  EXPECT_EQ(prefs.server_udp_port, 4665);
  EXPECT_EQ(prefs.ip_filter_level, 127);
  EXPECT_TRUE(prefs.enable_kad);
  EXPECT_TRUE(prefs.enable_ip_filter);
  EXPECT_TRUE(prefs.enable_obfuscation);
  EXPECT_GE(prefs.upload_slots, 1u);
  EXPECT_FALSE(prefs.incoming_dir.empty());
  EXPECT_FALSE(prefs.temp_dir.empty());
  EXPECT_FALSE(prefs.server_met_path.empty());
}

TEST(Preferences, RoundTripPreservesEngineFields) {
  auto prefs = Preferences::defaults();
  prefs.nickname = "alice";
  prefs.tcp_port = 5555;
  prefs.udp_port = 5556;
  prefs.server_udp_port = 5557;
  prefs.upload_limit_bps = 123456;
  prefs.download_limit_bps = 654321;
  prefs.upload_slots = 7;
  prefs.max_connections = 321;
  prefs.max_sources_per_file = 222;
  prefs.ip_filter_level = 99;
  prefs.enable_kad = false;
  prefs.enable_obfuscation = true;
  prefs.request_obfuscation = true;
  prefs.require_obfuscation = false;
  prefs.incoming_dir = "incoming-custom";
  prefs.temp_dir = "temp-custom";
  prefs.server_met_path = "lists/server.met";
  prefs.nodes_dat_path = "kad/nodes.dat";
  prefs.ipfilter_dat_path = "filters/ipfilter.dat";
  prefs.shared_dirs = {"share/a", "share/b"};

  const auto path = temp_path("ed2k_preferences_roundtrip.dat");
  auto saved = prefs.save(path);
  ASSERT_TRUE(saved.has_value()) << saved.error().message();

  auto loaded = Preferences::load(path);
  ASSERT_TRUE(loaded.has_value()) << loaded.error().message();
  EXPECT_EQ(*loaded, prefs);
  std::filesystem::remove(path);
}

TEST(Preferences, RejectsBadMagic) {
  const auto path = temp_path("ed2k_preferences_bad.dat");
  {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << "not preferences";
  }

  auto loaded = Preferences::load(path);
  ASSERT_FALSE(loaded.has_value());
  EXPECT_EQ(loaded.error(), ed2k::make_error_code(ed2k::errc::bad_magic));
  std::filesystem::remove(path);
}
