#include <ed2k/version.hpp>
#include <ed2k/core/hash.hpp>
#include <ed2k/hash/ed2k_hasher.hpp>
#include <ed2k/link/ed2k_link.hpp>
#include <ed2k/util/error.hpp>

#include <cstdio>
#include <cstring>

int main() {
  int fail = 0;

  // 1. Version available
  if (ed2k::version().empty()) { std::puts("FAIL: version empty"); ++fail; }

  // 2. Compile-time version constants
  static_assert(ED2K_VERSION_MAJOR >= 2, "major version");
  static_assert(ED2K_VERSION_AT_LEAST(2, 0, 0), "at-least check");

  // 3. Hash a small buffer
  const char data[] = "hello ed2k";
  auto hash = ed2k::hash_bytes(
      {reinterpret_cast<const std::byte*>(data), std::strlen(data)});
  if (hash.is_zero()) { std::puts("FAIL: hash is zero"); ++fail; }

  // 4. Parse an ed2k link
  auto link = ed2k::link::parse_link(
      "ed2k://|file|test.bin|1024|31D6CFE0D16AE931B73C59D7E0C089C0|/");
  if (!link) { std::puts("FAIL: link parse failed"); ++fail; }

  // 5. Error code category is registered
  std::error_code ec = ed2k::errc::timed_out;
  if (std::string(ec.category().name()) != "ed2k") {
    std::puts("FAIL: error category name");
    ++fail;
  }

  std::printf("consumer test: %s (%d failures)\n",
              fail ? "FAILED" : "PASSED", fail);
  return fail;
}
