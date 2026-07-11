#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <system_error>

#include <tl/expected.hpp>

namespace ed2k::infra::detail {

struct ParentDirectorySyncOps {
  std::function<int(const std::filesystem::path&)> open_directory;
  std::function<int(int)> sync_directory;
  std::function<int(int)> close_directory;
  std::function<int()> last_error;
};

tl::expected<void, std::error_code>
sync_parent_directory(const std::filesystem::path& destination,
                      const ParentDirectorySyncOps& ops);

#ifdef _WIN32

struct WindowsNativeFileOps {
  std::function<bool(const std::filesystem::path&,
                     const std::filesystem::path&,
                     const std::filesystem::path&)>
    replace_file;
  std::function<bool(const std::filesystem::path&, const std::filesystem::path&)>
    move_file;
  std::function<bool(const std::filesystem::path&)> remove_file;
  std::function<std::uint32_t()> last_error;
  std::function<bool(const std::filesystem::path&)> flush_file =
    [](const std::filesystem::path&) { return true; };
};

tl::expected<void, std::error_code>
replace_existing_file_windows(const std::filesystem::path& temporary,
                              const std::filesystem::path& destination,
                              const std::filesystem::path& backup,
                              const WindowsNativeFileOps& ops);

#endif

} // namespace ed2k::infra::detail
