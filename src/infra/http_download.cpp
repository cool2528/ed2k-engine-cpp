#include "ed2k/infra/http_download.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <optional>
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
#include <boost/asio/streambuf.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include "ed2k/util/error.hpp"

namespace ed2k::infra {
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

namespace {

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
  std::string input(target.substr(0, query_pos));
  const auto query = query_pos == std::string_view::npos ? std::string_view{} : target.substr(query_pos);
  std::string output;

  while (!input.empty()) {
    if (input.starts_with("../")) {
      input.erase(0, 3);
    } else if (input.starts_with("./")) {
      input.erase(0, 2);
    } else if (input.starts_with("/./")) {
      input.erase(0, 2);
    } else if (input == "/.") {
      input = "/";
    } else if (input.starts_with("/../")) {
      input.erase(0, 3);
      const auto slash = output.rfind('/');
      output.erase(slash == std::string::npos ? 0 : slash);
    } else if (input == "/..") {
      input = "/";
      const auto slash = output.rfind('/');
      output.erase(slash == std::string::npos ? 0 : slash);
    } else if (input == "." || input == "..") {
      input.clear();
    } else {
      const auto next = input.front() == '/' ? input.find('/', 1) : input.find('/');
      const auto count = next == std::string::npos ? input.size() : next;
      output.append(input, 0, count);
      input.erase(0, count);
    }
  }

  if (output.empty()) {
    output = "/";
  }
  output.append(query);
  return output;
}

tl::expected<ParsedURL, std::error_code> parse_url(std::string_view url) {
  const auto scheme_end = url.find("://");
  if (scheme_end == std::string_view::npos) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }

  ParsedURL out;
  const auto scheme = lower_ascii(std::string(url.substr(0, scheme_end)));
  if (scheme == "http") {
    out.scheme = URLScheme::http;
    out.port = 80;
  } else if (scheme == "https") {
    out.scheme = URLScheme::https;
    out.port = 443;
  } else {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }

  auto rest = url.substr(scheme_end + 3);
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

  if (location.find("://") != std::string_view::npos) {
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

std::string host_header(const ParsedURL& url) {
  const bool ipv6 = url.host.find(':') != std::string::npos;
  return (ipv6 ? "[" + url.host + "]" : url.host) + ":" + std::to_string(url.port);
}

asio::awaitable<tl::expected<HTTPResponse, std::error_code>>
request_http(asio::any_io_executor executor,
             const ParsedURL& parsed,
             std::chrono::milliseconds timeout) {
  tcp::resolver resolver(executor);
  auto [resolve_ec, endpoints] = co_await resolver.async_resolve(
    parsed.host,
    std::to_string(parsed.port),
    asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  if (resolve_ec) {
    co_return tl::unexpected(make_error_code(errc::connect_failed));
  }

  tcp::socket socket(executor);
  auto [connect_ec, endpoint] = co_await asio::async_connect(
    socket,
    endpoints,
    asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  (void)endpoint;
  if (connect_ec) {
    co_return tl::unexpected(make_error_code(
      connect_ec == asio::error::operation_aborted ? errc::timed_out : errc::connect_failed));
  }

  const std::string request =
    "GET " + parsed.target + " HTTP/1.1\r\n"
    "Host: " + host_header(parsed) + "\r\n"
    "Connection: close\r\n\r\n";
  auto [write_ec, written] = co_await asio::async_write(
    socket,
    asio::buffer(request),
    asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  (void)written;
  if (write_ec) {
    co_return tl::unexpected(make_error_code(errc::connection_closed));
  }

  asio::streambuf buffer;
  auto [header_ec, header_bytes] = co_await asio::async_read_until(
    socket,
    buffer,
    "\r\n\r\n",
    asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  (void)header_bytes;
  if (header_ec) {
    co_return tl::unexpected(make_error_code(
      header_ec == asio::error::operation_aborted ? errc::timed_out : errc::connection_closed));
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
  if (!response.head.content_length) {
    co_return response;
  }

  const auto expected_length = *response.head.content_length;
  response.body.reserve(expected_length);
  const auto body_start = header_end + 4;
  for (std::size_t i = body_start; i < buffered.size() && response.body.size() < expected_length; ++i) {
    response.body.push_back(static_cast<std::byte>(static_cast<unsigned char>(buffered[i])));
  }

  while (response.body.size() < expected_length) {
    std::array<char, 4096> chunk{};
    const auto need = std::min<std::size_t>(chunk.size(), expected_length - response.body.size());
    auto [read_ec, n] = co_await asio::async_read(
      socket,
      asio::buffer(chunk.data(), need),
      asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
    if (read_ec) {
      co_return tl::unexpected(make_error_code(
        read_ec == asio::error::operation_aborted ? errc::timed_out : errc::connection_closed));
    }
    for (std::size_t i = 0; i < n; ++i) {
      response.body.push_back(static_cast<std::byte>(static_cast<unsigned char>(chunk[i])));
    }
  }
  co_return response;
}

} // namespace

HTTPDownload::HTTPDownload(asio::any_io_executor ex) : executor_(std::move(ex)) {}

asio::awaitable<tl::expected<void, std::error_code>>
HTTPDownload::fetch(const std::string& url,
                    const std::filesystem::path& destination,
                    std::chrono::milliseconds timeout) {
  auto parsed = parse_url(url);
  if (!parsed) {
    co_return tl::unexpected(parsed.error());
  }

  constexpr std::size_t max_redirects = 5;
  std::size_t redirects = 0;
  std::unordered_set<std::string> visited;
  visited.insert(url_key(*parsed));

  while (true) {
    if (parsed->scheme == URLScheme::https) {
      co_return tl::unexpected(make_error_code(errc::unsupported_version));
    }

    auto response = co_await request_http(executor_, *parsed, timeout);
    if (!response) {
      co_return tl::unexpected(response.error());
    }

    if (success_status(response->head.status)) {
      if (!response->head.content_length) {
        co_return tl::unexpected(make_error_code(errc::server_protocol_error));
      }
      std::ofstream out(destination, std::ios::binary | std::ios::trunc);
      if (!out) {
        co_return tl::unexpected(make_error_code(errc::io_error));
      }
      out.write(reinterpret_cast<const char*>(response->body.data()),
                static_cast<std::streamsize>(response->body.size()));
      if (!out) {
        co_return tl::unexpected(make_error_code(errc::io_error));
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
    if (!visited.insert(url_key(*next)).second) {
      co_return tl::unexpected(make_error_code(errc::server_protocol_error));
    }
    parsed = std::move(next);
    ++redirects;
  }
}

} // namespace ed2k::infra
