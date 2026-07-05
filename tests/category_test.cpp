#include <array>

#include <gtest/gtest.h>

#include "ed2k/infra/category.hpp"
#include "ed2k/infra/preferences.hpp"

using namespace ed2k;

TEST(Category, RoundTripPreservesCategoryDefinitions) {
  infra::Category movies{1, "movies", "incoming/movies", ".*\\.(avi|mkv)$"};
  infra::Category audio{2, "audio", "incoming/audio", ".*\\.mp3$"};

  auto bytes = infra::write_categories(std::array<infra::Category, 2>{movies, audio});
  auto parsed = infra::parse_categories(bytes);

  ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
  ASSERT_EQ(parsed->size(), 2u);
  EXPECT_EQ((*parsed)[0], movies);
  EXPECT_EQ((*parsed)[1], audio);
}

TEST(Category, PreferencesRoundTripPersistsCategories) {
  infra::Preferences prefs = infra::Preferences::defaults();
  prefs.categories.push_back({3, "books", "incoming/books", ".*\\.(pdf|epub)$"});

  const auto path = std::filesystem::temp_directory_path() / "ed2k_preferences_categories.dat";
  auto saved = prefs.save(path);
  ASSERT_TRUE(saved.has_value()) << saved.error().message();

  auto loaded = infra::Preferences::load(path);
  ASSERT_TRUE(loaded.has_value()) << loaded.error().message();
  ASSERT_EQ(loaded->categories.size(), 1u);
  EXPECT_EQ(loaded->categories[0], prefs.categories[0]);
  std::filesystem::remove(path);
}

TEST(Category, SelectsArchivePathByRegexInListOrder) {
  infra::CategoryList categories;
  categories.add({1, "video", "incoming/video", ".*\\.(avi|mkv)$"});
  categories.add({2, "generic", "incoming/other", ".*"});

  EXPECT_EQ(categories.archive_path_for("sample.mkv"), std::filesystem::path("incoming/video") / "sample.mkv");
  EXPECT_EQ(categories.archive_path_for("readme.txt"), std::filesystem::path("incoming/other") / "readme.txt");
}
