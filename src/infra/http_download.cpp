#include "ed2k/infra/http_download.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <openssl/ssl.h>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "ed2k/util/error.hpp"
#include "infra/http_download_internal.hpp"
#include "infra/tls_trust_store.hpp"

namespace ed2k::infra {
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

namespace detail {

bool operation_not_supported(int error) {
#ifdef ENOTSUP
  if (error == ENOTSUP) {
    return true;
  }
#endif
#ifdef EOPNOTSUPP
  if (error == EOPNOTSUPP) {
    return true;
  }
#endif
  return false;
}

bool parent_directory_fsync_unsupported(int error) {
  // Linux and several Unix filesystems use EINVAL when directory fsync is not
  // implemented. ENOTSUP/EOPNOTSUPP explicitly mean the same thing.
  return error == EINVAL || operation_not_supported(error);
}

tl::expected<void, std::error_code>
sync_parent_directory(const std::filesystem::path& destination,
                      const ParentDirectorySyncOps& ops) {
  const auto parent = destination.parent_path().empty()
    ? std::filesystem::path(".")
    : destination.parent_path();
  int descriptor = -1;
  int open_error = 0;
  do {
    descriptor = ops.open_directory(parent);
    if (descriptor < 0) {
      open_error = ops.last_error();
    }
  } while (descriptor < 0 && open_error == EINTR);
  if (descriptor < 0) {
    // Only explicit operation-not-supported errors mean O_DIRECTORY is
    // unavailable. EINVAL and all other errors are genuine open failures.
    if (operation_not_supported(open_error)) {
      return {};
    }
    return tl::unexpected(make_error_code(errc::io_error));
  }

  int sync_result = 0;
  int sync_error = 0;
  do {
    sync_result = ops.sync_directory(descriptor);
    if (sync_result != 0) {
      sync_error = ops.last_error();
    }
  } while (sync_result != 0 && sync_error == EINTR);

  const int close_result = ops.close_directory(descriptor);
  if (sync_result != 0 && !parent_directory_fsync_unsupported(sync_error)) {
    return tl::unexpected(make_error_code(errc::io_error));
  }
  if (close_result != 0) {
    // Do not retry close after EINTR: on Linux the descriptor has already been
    // released, and a retry could close an unrelated descriptor reused by
    // another thread.
    return tl::unexpected(make_error_code(errc::io_error));
  }
  return {};
}

#ifdef _WIN32
tl::expected<void, std::error_code>
replace_existing_file_windows(const std::filesystem::path& temporary,
                              const std::filesystem::path& destination,
                              const std::filesystem::path& backup,
                              const WindowsNativeFileOps& ops) {
  if (backup.empty()) {
    return tl::unexpected(make_error_code(errc::io_error));
  }
  if (ops.replace_file(destination, temporary, backup)) {
    if (!ops.flush_file(destination)) {
      return tl::unexpected(make_error_code(errc::io_error));
    }
    if (!ops.remove_file(backup)) {
      return tl::unexpected(make_error_code(errc::io_error));
    }
    return {};
  }

  const auto error = ops.last_error();
  if (error == ERROR_UNABLE_TO_MOVE_REPLACEMENT_2) {
    ops.move_file(backup, destination);
    ops.remove_file(temporary);
    return tl::unexpected(make_error_code(errc::io_error));
  }

  if (error == ERROR_UNABLE_TO_REMOVE_REPLACED ||
      error == ERROR_UNABLE_TO_MOVE_REPLACEMENT) {
    ops.remove_file(temporary);
    return tl::unexpected(make_error_code(errc::io_error));
  }

  // Microsoft documents that all other failures retain both original names
  // and do not create the backup, so only the replacement temp is disposable.
  ops.remove_file(temporary);
  return tl::unexpected(make_error_code(errc::io_error));
}
#endif

} // namespace detail

namespace {

constexpr std::size_t max_response_header_bytes = 64U * 1024U;
constexpr std::size_t max_response_body_bytes = 256U * 1024U * 1024U;
using Deadline = std::chrono::steady_clock::time_point;

enum class URLScheme { http, https };

struct ParsedURL {
  URLScheme scheme = URLScheme::http;
  std::string host;
  std::uint16_t port = 80;
  std::string target = "/";
};

struct ResponseHead {
  unsigned status = 0;
  std::optional<std::size_t> content_length;
  std::optional<std::string> location;
};

struct HTTPResponse {
  ResponseHead head;
  std::vector<std::byte> body;
};

std::string lower_ascii(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return text;
}

std::string_view trim_ascii(std::string_view text) {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
    text.remove_prefix(1);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
    text.remove_suffix(1);
  }
  return text;
}

bool ascii_alpha(char c) {
  const auto uc = static_cast<unsigned char>(c);
  return (uc >= 'A' && uc <= 'Z') || (uc >= 'a' && uc <= 'z');
}

bool uri_scheme_char(char c) {
  const auto uc = static_cast<unsigned char>(c);
  return ascii_alpha(c) || (uc >= '0' && uc <= '9') || c == '+' || c == '-' || c == '.';
}

std::optional<std::size_t> uri_scheme_end(std::string_view reference) {
  if (reference.empty() || !ascii_alpha(reference.front())) {
    return std::nullopt;
  }
  for (std::size_t i = 1; i < reference.size(); ++i) {
    if (reference[i] == ':') {
      return i;
    }
    if (!uri_scheme_char(reference[i])) {
      return std::nullopt;
    }
  }
  return std::nullopt;
}

tl::expected<std::uint16_t, std::error_code> parse_port(std::string_view text) {
  std::uint32_t port = 0;
  auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), port);
  if (ec != std::errc{} || ptr != text.data() + text.size() || port == 0 || port > 65535) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }
  return static_cast<std::uint16_t>(port);
}

std::string remove_dot_segments(std::string_view target) {
  const auto query_pos = target.find('?');
  const auto path = target.substr(0, query_pos);
  const auto query = query_pos == std::string_view::npos ? std::string_view{} : target.substr(query_pos);
  const bool absolute = !path.empty() && path.front() == '/';
  std::vector<std::string_view> segments;
  std::size_t pos = absolute ? 1 : 0;
  while (pos <= path.size()) {
    const auto slash = path.find('/', pos);
    const auto segment = path.substr(pos, slash == std::string_view::npos ? path.size() - pos
                                                                          : slash - pos);
    const bool last = slash == std::string_view::npos;
    if (segment == "..") {
      if (!segments.empty()) {
        segments.pop_back();
      }
      if (last) {
        segments.emplace_back();
      }
    } else if (segment == ".") {
      if (last) {
        segments.emplace_back();
      }
    } else {
      segments.push_back(segment);
    }
    if (last) {
      break;
    }
    pos = slash + 1;
  }

  std::string output;
  output.reserve(path.size() + query.size());
  if (absolute) {
    output.push_back('/');
  }
  for (std::size_t i = 0; i < segments.size(); ++i) {
    if (i != 0) {
      output.push_back('/');
    }
    output.append(segments[i]);
  }
  if (output.empty()) {
    output = absolute ? "/" : std::string{};
  }
  output.append(query);
  return output;
}

tl::expected<ParsedURL, std::error_code> parse_url(std::string_view url) {
  const auto scheme_end = uri_scheme_end(url);
  if (!scheme_end || url.substr(*scheme_end, 3) != "://") {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }

  ParsedURL out;
  const auto scheme = lower_ascii(std::string(url.substr(0, *scheme_end)));
  if (scheme == "http") {
    out.scheme = URLScheme::http;
    out.port = 80;
  } else if (scheme == "https") {
    out.scheme = URLScheme::https;
    out.port = 443;
  } else {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }

  auto rest = url.substr(*scheme_end + 3);
  const auto authority_end = rest.find_first_of("/?#");
  const auto authority = rest.substr(0, authority_end);
  if (authority.empty() || authority.find('@') != std::string_view::npos) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }

  if (authority.front() == '[') {
    const auto bracket = authority.find(']');
    if (bracket == std::string_view::npos) {
      return tl::unexpected(make_error_code(errc::malformed_link));
    }
    out.host.assign(authority.substr(1, bracket - 1));
    const auto suffix = authority.substr(bracket + 1);
    if (!suffix.empty()) {
      if (suffix.front() != ':') {
        return tl::unexpected(make_error_code(errc::malformed_link));
      }
      auto port = parse_port(suffix.substr(1));
      if (!port) {
        return tl::unexpected(port.error());
      }
      out.port = *port;
    }
  } else {
    const auto colon = authority.rfind(':');
    if (colon != std::string_view::npos) {
      if (authority.find(':') != colon) {
        return tl::unexpected(make_error_code(errc::malformed_link));
      }
      out.host.assign(authority.substr(0, colon));
      auto port = parse_port(authority.substr(colon + 1));
      if (!port) {
        return tl::unexpected(port.error());
      }
      out.port = *port;
    } else {
      out.host.assign(authority);
    }
  }
  if (out.host.empty()) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }

  if (authority_end != std::string_view::npos && rest[authority_end] != '#') {
    auto raw_target = rest.substr(authority_end);
    const auto fragment = raw_target.find('#');
    raw_target = raw_target.substr(0, fragment);
    out.target = raw_target.front() == '?' ? "/" + std::string(raw_target)
                                           : std::string(raw_target);
  }
  if (out.host.find_first_of("\r\n") != std::string::npos ||
      out.target.find_first_of("\r\n") != std::string::npos) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }
  return out;
}

std::string scheme_name(URLScheme scheme) {
  return scheme == URLScheme::http ? "http" : "https";
}

std::string url_key(const ParsedURL& url) {
  return scheme_name(url.scheme) + "://" + lower_ascii(url.host) + ":" +
         std::to_string(url.port) + url.target;
}

tl::expected<ParsedURL, std::error_code>
resolve_location(const ParsedURL& base, std::string_view location) {
  location = trim_ascii(location);
  const auto fragment = location.find('#');
  location = location.substr(0, fragment);
  if (location.empty()) {
    return base;
  }

  if (uri_scheme_end(location)) {
    return parse_url(location);
  }
  if (location.starts_with("//")) {
    return parse_url(scheme_name(base.scheme) + ":" + std::string(location));
  }

  ParsedURL resolved = base;
  if (location.front() == '/') {
    resolved.target = std::string(location);
  } else if (location.front() == '?') {
    const auto query = base.target.find('?');
    resolved.target = base.target.substr(0, query) + std::string(location);
  } else {
    const auto query = base.target.find('?');
    const auto base_path = std::string_view(base.target).substr(0, query);
    const auto slash = base_path.rfind('/');
    const auto directory = base_path.substr(0, slash == std::string_view::npos ? 0 : slash + 1);
    resolved.target = remove_dot_segments(std::string(directory) + std::string(location));
  }
  return resolved;
}

tl::expected<ResponseHead, std::error_code> parse_response_head(std::string_view headers) {
  const auto status_end = headers.find("\r\n");
  if (status_end == std::string_view::npos) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }

  const auto status_line = headers.substr(0, status_end);
  if (!status_line.starts_with("HTTP/")) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  const auto first_space = status_line.find(' ');
  if (first_space == std::string_view::npos) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  auto status_text = status_line.substr(first_space + 1);
  while (!status_text.empty() && status_text.front() == ' ') {
    status_text.remove_prefix(1);
  }
  if (status_text.size() < 3) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }

  ResponseHead out;
  auto [status_ptr, status_ec] =
    std::from_chars(status_text.data(), status_text.data() + 3, out.status);
  if (status_ec != std::errc{} || status_ptr != status_text.data() + 3 ||
      (status_text.size() > 3 && status_text[3] != ' ')) {
    return tl::unexpected(make_error_code(errc::server_protocol_error));
  }

  std::size_t pos = status_end + 2;
  while (pos < headers.size()) {
    const auto end = headers.find("\r\n", pos);
    const auto line = headers.substr(pos, end == std::string_view::npos ? headers.size() - pos : end - pos);
    if (line.empty()) {
      break;
    }
    const auto colon = line.find(':');
    if (colon == std::string_view::npos) {
      return tl::unexpected(make_error_code(errc::server_protocol_error));
    }
    const auto name = lower_ascii(std::string(trim_ascii(line.substr(0, colon))));
    const auto value = trim_ascii(line.substr(colon + 1));
    if (name == "content-length") {
      std::size_t length = 0;
      auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), length);
      if (ec != std::errc{} || ptr != value.data() + value.size() ||
          (out.content_length && *out.content_length != length)) {
        return tl::unexpected(make_error_code(errc::server_protocol_error));
      }
      out.content_length = length;
    } else if (name == "location") {
      if (value.empty() || out.location) {
        return tl::unexpected(make_error_code(errc::server_protocol_error));
      }
      out.location = std::string(value);
    }
    if (end == std::string_view::npos) {
      break;
    }
    pos = end + 2;
  }
  return out;
}

bool success_status(unsigned status) {
  return status >= 200 && status < 300;
}

bool redirect_status(unsigned status) {
  return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

std::filesystem::path unique_sibling_path(const std::filesystem::path& destination,
                                          const std::filesystem::path& suffix) {
  static std::atomic<std::uint64_t> next_id{0};
  const auto timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
  std::filesystem::path name = ".ed2k-http-";
  name += std::to_string(timestamp);
  name += ".";
  name += std::to_string(next_id.fetch_add(1, std::memory_order_relaxed));
  name += suffix;
  return destination.parent_path() / name;
}

void remove_best_effort(const std::filesystem::path& path) {
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
}

#ifdef _WIN32
detail::WindowsNativeFileOps windows_native_file_ops() {
  return {
    [](const std::filesystem::path& destination,
       const std::filesystem::path& temporary,
       const std::filesystem::path& backup) {
      return ReplaceFileW(destination.c_str(),
                          temporary.c_str(),
                          backup.empty() ? nullptr : backup.c_str(),
                          0,
                          nullptr,
                          nullptr) != 0;
    },
    [](const std::filesystem::path& from, const std::filesystem::path& to) {
      return MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_WRITE_THROUGH) != 0;
    },
    [](const std::filesystem::path& path) { return DeleteFileW(path.c_str()) != 0; },
    [] { return static_cast<std::uint32_t>(GetLastError()); },
    [](const std::filesystem::path& path) {
      const HANDLE handle = CreateFileW(path.c_str(),
                                        GENERIC_WRITE,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        nullptr,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        nullptr);
      if (handle == INVALID_HANDLE_VALUE) {
        return false;
      }
      const bool flushed = FlushFileBuffers(handle) != 0;
      const bool closed = CloseHandle(handle) != 0;
      return flushed && closed;
    },
  };
}
#else
detail::ParentDirectorySyncOps parent_directory_sync_ops() {
  return {
    [](const std::filesystem::path& path) {
      return ::open(path.c_str(), O_RDONLY | O_DIRECTORY);
    },
    [](int descriptor) { return ::fsync(descriptor); },
    [](int descriptor) { return ::close(descriptor); },
    [] { return errno; },
  };
}
#endif

tl::expected<void, std::error_code>
replace_destination(const std::filesystem::path& temporary,
                    const std::filesystem::path& destination) {
#ifdef _WIN32
  const DWORD attributes = GetFileAttributesW(destination.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    const DWORD error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
      remove_best_effort(temporary);
      return tl::unexpected(make_error_code(errc::io_error));
    }
    if (MoveFileExW(temporary.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH)) {
      return {};
    }
    remove_best_effort(temporary);
    return tl::unexpected(make_error_code(errc::io_error));
  }
  if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
    remove_best_effort(temporary);
    return tl::unexpected(make_error_code(errc::io_error));
  }
  const auto backup = unique_sibling_path(destination, ".bak");
  return detail::replace_existing_file_windows(
    temporary, destination, backup, windows_native_file_ops());
#else
  std::error_code rename_error;
  std::filesystem::rename(temporary, destination, rename_error);
  if (!rename_error) {
    return detail::sync_parent_directory(destination, parent_directory_sync_ops());
  }
  remove_best_effort(temporary);
  return tl::unexpected(make_error_code(errc::io_error));
#endif
}

tl::expected<std::filesystem::path, std::error_code>
write_temporary_file(const std::filesystem::path& destination,
                     const std::vector<std::byte>& body) {
  constexpr std::size_t max_attempts = 100;
  for (std::size_t attempt = 0; attempt < max_attempts; ++attempt) {
    const auto temporary = unique_sibling_path(destination, ".tmp");
    std::FILE* stream = nullptr;
#ifdef _WIN32
    const auto open_error = _wfopen_s(&stream, temporary.c_str(), L"wbx");
    if (open_error == EEXIST) {
      continue;
    }
    if (open_error != 0 || stream == nullptr) {
      return tl::unexpected(make_error_code(errc::io_error));
    }
#else
    errno = 0;
    stream = std::fopen(temporary.c_str(), "wbx");
    if (stream == nullptr && errno == EEXIST) {
      continue;
    }
    if (stream == nullptr) {
      return tl::unexpected(make_error_code(errc::io_error));
    }
#endif

    const bool write_ok =
      body.empty() || std::fwrite(body.data(), 1, body.size(), stream) == body.size();
    const bool flush_ok = write_ok && std::fflush(stream) == 0;
#ifdef _WIN32
    const bool sync_ok = flush_ok && _commit(_fileno(stream)) == 0;
#else
    bool sync_ok = flush_ok;
    if (sync_ok) {
      int sync_result = 0;
      do {
        sync_result = ::fsync(fileno(stream));
      } while (sync_result != 0 && errno == EINTR);
      sync_ok = sync_result == 0;
    }
#endif
    const bool close_ok = std::fclose(stream) == 0;
    if (!write_ok || !flush_ok || !sync_ok || !close_ok) {
      remove_best_effort(temporary);
      return tl::unexpected(make_error_code(errc::io_error));
    }
    return temporary;
  }
  return tl::unexpected(make_error_code(errc::io_error));
}

tl::expected<void, std::error_code>
write_and_replace(const std::filesystem::path& destination,
                  const std::vector<std::byte>& body) {
  auto temporary = write_temporary_file(destination, body);
  if (!temporary) {
    return tl::unexpected(temporary.error());
  }
  auto replaced = replace_destination(*temporary, destination);
  if (!replaced) {
    return tl::unexpected(replaced.error());
  }
  return {};
}

std::string host_header(const ParsedURL& url) {
  const bool ipv6 = url.host.find(':') != std::string::npos;
  return (ipv6 ? "[" + url.host + "]" : url.host) + ":" + std::to_string(url.port);
}

std::optional<std::chrono::steady_clock::duration> remaining_until(Deadline deadline) {
  const auto now = std::chrono::steady_clock::now();
  if (now >= deadline) {
    return std::nullopt;
  }
  return deadline - now;
}

bool operation_timed_out(const boost::system::error_code& error, Deadline deadline) {
  return error == asio::error::operation_aborted ||
         std::chrono::steady_clock::now() >= deadline;
}

template <class Stream>
asio::awaitable<tl::expected<HTTPResponse, std::error_code>>
request_over_stream(Stream& stream, const ParsedURL& parsed, Deadline deadline) {
  const std::string request =
    "GET " + parsed.target + " HTTP/1.1\r\n"
    "Host: " + host_header(parsed) + "\r\n"
    "Connection: close\r\n\r\n";
  auto remaining = remaining_until(deadline);
  if (!remaining) {
    co_return tl::unexpected(make_error_code(errc::timed_out));
  }
  auto [write_ec, written] = co_await asio::async_write(
    stream,
    asio::buffer(request),
    asio::cancel_after(*remaining, asio::as_tuple(asio::use_awaitable)));
  (void)written;
  if (write_ec) {
    co_return tl::unexpected(make_error_code(
      operation_timed_out(write_ec, deadline) ? errc::timed_out : errc::connection_closed));
  }

  asio::streambuf buffer(max_response_header_bytes);
  remaining = remaining_until(deadline);
  if (!remaining) {
    co_return tl::unexpected(make_error_code(errc::timed_out));
  }
  auto [header_ec, header_bytes] = co_await asio::async_read_until(
    stream,
    buffer,
    "\r\n\r\n",
    asio::cancel_after(*remaining, asio::as_tuple(asio::use_awaitable)));
  (void)header_bytes;
  if (header_ec) {
    if (header_ec == asio::error::not_found || buffer.size() >= max_response_header_bytes) {
      co_return tl::unexpected(make_error_code(errc::server_protocol_error));
    }
    co_return tl::unexpected(make_error_code(
      operation_timed_out(header_ec, deadline) ? errc::timed_out : errc::connection_closed));
  }

  std::string buffered(asio::buffers_begin(buffer.data()), asio::buffers_end(buffer.data()));
  const auto header_end = buffered.find("\r\n\r\n");
  if (header_end == std::string::npos) {
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  auto head = parse_response_head(std::string_view(buffered).substr(0, header_end + 2));
  if (!head) {
    co_return tl::unexpected(head.error());
  }

  HTTPResponse response{std::move(*head), {}};
  if (!success_status(response.head.status)) {
    co_return response;
  }
  if (!response.head.content_length) {
    co_return response;
  }

  const auto expected_length = *response.head.content_length;
  if (expected_length > max_response_body_bytes) {
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  try {
    response.body.reserve(expected_length);
  } catch (const std::length_error&) {
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));
  } catch (const std::bad_alloc&) {
    co_return tl::unexpected(make_error_code(errc::io_error));
  }
  const auto body_start = header_end + 4;
  for (std::size_t i = body_start; i < buffered.size() && response.body.size() < expected_length; ++i) {
    response.body.push_back(static_cast<std::byte>(static_cast<unsigned char>(buffered[i])));
  }

  while (response.body.size() < expected_length) {
    std::array<char, 4096> chunk{};
    const auto need = std::min<std::size_t>(chunk.size(), expected_length - response.body.size());
    remaining = remaining_until(deadline);
    if (!remaining) {
      co_return tl::unexpected(make_error_code(errc::timed_out));
    }
    auto [read_ec, n] = co_await asio::async_read(
      stream,
      asio::buffer(chunk.data(), need),
      asio::cancel_after(*remaining, asio::as_tuple(asio::use_awaitable)));
    if (read_ec) {
      co_return tl::unexpected(make_error_code(
        operation_timed_out(read_ec, deadline) ? errc::timed_out : errc::connection_closed));
    }
    for (std::size_t i = 0; i < n; ++i) {
      response.body.push_back(static_cast<std::byte>(static_cast<unsigned char>(chunk[i])));
    }
  }
  co_return response;
}

asio::awaitable<tl::expected<HTTPResponse, std::error_code>>
request_http(asio::any_io_executor executor,
             const ParsedURL& parsed,
             Deadline deadline) {
  tcp::resolver resolver(executor);
  auto remaining = remaining_until(deadline);
  if (!remaining) {
    co_return tl::unexpected(make_error_code(errc::timed_out));
  }
  auto [resolve_ec, endpoints] = co_await resolver.async_resolve(
    parsed.host,
    std::to_string(parsed.port),
    asio::cancel_after(*remaining, asio::as_tuple(asio::use_awaitable)));
  if (resolve_ec) {
    co_return tl::unexpected(make_error_code(
      operation_timed_out(resolve_ec, deadline) ? errc::timed_out : errc::connect_failed));
  }

  tcp::socket socket(executor);
  remaining = remaining_until(deadline);
  if (!remaining) {
    co_return tl::unexpected(make_error_code(errc::timed_out));
  }
  auto [connect_ec, endpoint] = co_await asio::async_connect(
    socket,
    endpoints,
    asio::cancel_after(*remaining, asio::as_tuple(asio::use_awaitable)));
  (void)endpoint;
  if (connect_ec) {
    co_return tl::unexpected(make_error_code(
      operation_timed_out(connect_ec, deadline) ? errc::timed_out : errc::connect_failed));
  }

  co_return co_await request_over_stream(socket, parsed, deadline);
}

asio::awaitable<tl::expected<HTTPResponse, std::error_code>>
request_https(asio::any_io_executor executor,
              asio::ssl::context& context,
              const ParsedURL& parsed,
              Deadline deadline) {
  tcp::resolver resolver(executor);
  auto remaining = remaining_until(deadline);
  if (!remaining) {
    co_return tl::unexpected(make_error_code(errc::timed_out));
  }
  auto [resolve_ec, endpoints] = co_await resolver.async_resolve(
    parsed.host,
    std::to_string(parsed.port),
    asio::cancel_after(*remaining, asio::as_tuple(asio::use_awaitable)));
  if (resolve_ec) {
    co_return tl::unexpected(make_error_code(
      operation_timed_out(resolve_ec, deadline) ? errc::timed_out : errc::connect_failed));
  }

  asio::ssl::stream<tcp::socket> stream(executor, context);
  remaining = remaining_until(deadline);
  if (!remaining) {
    co_return tl::unexpected(make_error_code(errc::timed_out));
  }
  auto [connect_ec, endpoint] = co_await asio::async_connect(
    stream.next_layer(),
    endpoints,
    asio::cancel_after(*remaining, asio::as_tuple(asio::use_awaitable)));
  (void)endpoint;
  if (connect_ec) {
    co_return tl::unexpected(make_error_code(
      operation_timed_out(connect_ec, deadline) ? errc::timed_out : errc::connect_failed));
  }

  if (SSL_set_tlsext_host_name(stream.native_handle(), parsed.host.c_str()) != 1) {
    ERR_clear_error();
    co_return tl::unexpected(make_error_code(errc::tls_error));
  }
  stream.set_verify_callback(asio::ssl::host_name_verification(parsed.host));

  remaining = remaining_until(deadline);
  if (!remaining) {
    co_return tl::unexpected(make_error_code(errc::timed_out));
  }
  auto [handshake_ec] = co_await stream.async_handshake(
    asio::ssl::stream_base::client,
    asio::cancel_after(*remaining, asio::as_tuple(asio::use_awaitable)));
  if (handshake_ec) {
    co_return tl::unexpected(make_error_code(
      operation_timed_out(handshake_ec, deadline) ? errc::timed_out : errc::tls_error));
  }

  co_return co_await request_over_stream(stream, parsed, deadline);
}

} // namespace

HTTPDownload::HTTPDownload(asio::any_io_executor ex, HTTPDownloadOptions options)
    : executor_(std::move(ex)), options_(std::move(options)) {}

asio::awaitable<tl::expected<void, std::error_code>>
HTTPDownload::fetch(const std::string& url,
                    const std::filesystem::path& destination,
                    std::chrono::milliseconds timeout) {
  auto parsed = parse_url(url);
  if (!parsed) {
    co_return tl::unexpected(parsed.error());
  }
  const auto deadline = std::chrono::steady_clock::now() + timeout;

  constexpr std::size_t max_redirects = 5;
  std::size_t redirects = 0;
  std::unordered_set<std::string> visited;
  visited.insert(url_key(*parsed));
  std::unique_ptr<asio::ssl::context> tls_context;

  while (true) {
    if (parsed->scheme == URLScheme::https && !tls_context) {
      auto created = create_tls_client_context(options_.additional_ca_file);
      if (!created) {
        co_return tl::unexpected(created.error());
      }
      tls_context = std::move(*created);
    }

    tl::expected<HTTPResponse, std::error_code> response =
      tl::unexpected(make_error_code(errc::connect_failed));
    if (parsed->scheme == URLScheme::https) {
      response = co_await request_https(executor_, *tls_context, *parsed, deadline);
    } else {
      response = co_await request_http(executor_, *parsed, deadline);
    }
    if (!response) {
      co_return tl::unexpected(response.error());
    }

    if (success_status(response->head.status)) {
      if (!response->head.content_length) {
        co_return tl::unexpected(make_error_code(errc::server_protocol_error));
      }
      auto written = write_and_replace(destination, response->body);
      if (!written) {
        co_return tl::unexpected(written.error());
      }
      co_return tl::expected<void, std::error_code>{};
    }

    if (!redirect_status(response->head.status) || !response->head.location ||
        redirects >= max_redirects) {
      co_return tl::unexpected(make_error_code(errc::server_protocol_error));
    }

    auto next = resolve_location(*parsed, *response->head.location);
    if (!next) {
      co_return tl::unexpected(next.error());
    }
    if (parsed->scheme == URLScheme::https && next->scheme == URLScheme::http) {
      co_return tl::unexpected(make_error_code(errc::server_protocol_error));
    }
    if (!visited.insert(url_key(*next)).second) {
      co_return tl::unexpected(make_error_code(errc::server_protocol_error));
    }
    parsed = std::move(next);
    ++redirects;
  }
}

} // namespace ed2k::infra
