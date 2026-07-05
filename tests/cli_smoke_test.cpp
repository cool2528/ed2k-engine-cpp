#include <gtest/gtest.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#ifndef _WIN32
#  include <sys/wait.h>
#endif
#include "ed2k/kad/nodes_dat.hpp"
#include "ed2k/util/log.hpp"

namespace {
std::optional<std::filesystem::path> find_tool() {
#ifdef _WIN32
  constexpr const char* exe = "ed2k-tool.exe";
#else
  constexpr const char* exe = "ed2k-tool";
#endif
  const auto cwd = std::filesystem::current_path();
  const std::filesystem::path candidates[] = {
      cwd / exe,
      cwd / "Debug" / exe,
      cwd / "Release" / exe,
      cwd.parent_path() / exe,
      cwd.parent_path() / "Debug" / exe,
      cwd.parent_path() / "Release" / exe,
  };
  for (const auto& candidate : candidates) {
    if (std::filesystem::exists(candidate)) {
      return candidate;
    }
  }
  return std::nullopt;
}

int shell_exit_code(int rc) {
#ifdef _WIN32
  return rc;
#else
  if (WIFEXITED(rc)) {
    return WEXITSTATUS(rc);
  }
  return rc;
#endif
}

std::string shell_path(const std::filesystem::path& path) {
  return path.generic_string();
}
} // namespace

TEST(CliLog, LoggerAvailable){
  auto& lg = ed2k::log();
  lg.info("cli smoke");
  SUCCEED();
}

TEST(CliKad, BootstrapAcceptsNodesDatFile) {
  auto tool = find_tool();
  if (!tool) {
    GTEST_SKIP() << "ed2k-tool executable not built";
  }

  const auto path = std::filesystem::temp_directory_path() / "ed2k_cli_kad_nodes.dat";
  const auto bytes = ed2k::kad::write_nodes_dat({});
  {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  }

#ifdef _WIN32
  const std::string redirect = " > NUL";
#else
  const std::string redirect = " > /dev/null";
#endif
  const auto command = shell_path(*tool) + " kad-bootstrap " + shell_path(path) + redirect;
  EXPECT_EQ(shell_exit_code(std::system(command.c_str())), 0);
  std::filesystem::remove(path);
}
