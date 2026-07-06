#include <gtest/gtest.h>

#include <type_traits>

#include "ed2k/download/download.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/net/connection.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/server/connection.hpp"

namespace {
template <class T>
constexpr bool is_small_pimpl_handle() {
  return sizeof(T) <= 3 * sizeof(void*);
}
}

TEST(ApiPimpl, PublicAsyncTypesExposeSmallMoveOnlyHandles) {
  EXPECT_TRUE(is_small_pimpl_handle<ed2k::net::IoRuntime>());
  EXPECT_TRUE(is_small_pimpl_handle<ed2k::net::Connection>());
  EXPECT_TRUE(is_small_pimpl_handle<ed2k::server::ServerConnection>());
  EXPECT_TRUE(is_small_pimpl_handle<ed2k::peer::C2CConnection>());
  EXPECT_TRUE(is_small_pimpl_handle<ed2k::download::PartFile>());
  EXPECT_TRUE(is_small_pimpl_handle<ed2k::download::MultiSourceDownload>());

  static_assert(!std::is_copy_constructible_v<ed2k::net::IoRuntime>);
  static_assert(!std::is_copy_constructible_v<ed2k::net::Connection>);
  static_assert(!std::is_copy_constructible_v<ed2k::server::ServerConnection>);
  static_assert(!std::is_copy_constructible_v<ed2k::peer::C2CConnection>);
  static_assert(!std::is_copy_constructible_v<ed2k::download::PartFile>);
  static_assert(!std::is_copy_constructible_v<ed2k::download::MultiSourceDownload>);
}
