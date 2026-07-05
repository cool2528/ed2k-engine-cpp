#include "ed2k/infra/http_download.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <fstream>
#include <iterator>
#include <string_view>
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

struct ParsedURL {
  std::string host;
  std::uint16_t port = 80;
  std::string path = "/";
};

tl::expected<std::uint16_t, std::error_code> parse_port(std::string_view text) {
  std::uint32_t port = 0;
  auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), port);
  if (ec != std::errc{} || ptr != text.data() + text.size() || port == 0 || port > 65535) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }
  return static_cast<std::uint16_t>(port);
}

tl::expected<ParsedURL, std::error_code> parse_http_url(std::string_view url) {
  constexpr std::string_view http = "http://";
  constexpr std::string_view https = "https://";
  if (url.substr(0, https.size()) == https) {
    return tl::unexpected(make_error_code(errc::unsupported_version));
  }
  if (url.substr(0, http.size()) != http) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }

  ParsedURL out;
  auto rest = url.substr(http.size());
  const auto slash = rest.find('/');
  const auto authority = rest.substr(0, slash);
  out.path = slash == std::string_view::npos ? "/" : std::string(rest.substr(slash));
  if (authority.empty()) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }

  const auto colon = authority.rfind(':');
  if (colon != std::string_view::npos) {
    out.host.assign(authority.substr(0, colon));
    auto port = parse_port(authority.substr(colon + 1));
    if (!port) {
      return tl::unexpected(port.error());
    }
    out.port = *port;
  } else {
    out.host.assign(authority);
  }
  if (out.host.empty()) {
    return tl::unexpected(make_error_code(errc::malformed_link));
  }
  return out;
}

std::string lower_ascii(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return text;
}

tl::expected<std::size_t, std::error_code> content_length_from(std::string_view headers) {
  std::size_t pos = 0;
  while (pos < headers.size()) {
    const auto end = headers.find("\r\n", pos);
    const auto line = headers.substr(pos, end == std::string_view::npos ? headers.size() - pos : end - pos);
    const auto colon = line.find(':');
    if (colon != std::string_view::npos) {
      auto name = lower_ascii(std::string(line.substr(0, colon)));
      if (name == "content-length") {
        auto value = line.substr(colon + 1);
        while (!value.empty() && value.front() == ' ') {
          value.remove_prefix(1);
        }
        std::size_t length = 0;
        auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), length);
        if (ec == std::errc{} && ptr == value.data() + value.size()) {
          return length;
        }
      }
    }
    if (end == std::string_view::npos) {
      break;
    }
    pos = end + 2;
  }
  return tl::unexpected(make_error_code(errc::server_protocol_error));
}

bool success_status(std::string_view headers) {
  const auto end = headers.find("\r\n");
  const auto status = headers.substr(0, end == std::string_view::npos ? headers.size() : end);
  return status.find(" 200 ") != std::string_view::npos || status.ends_with(" 200");
}

} // namespace

HTTPDownload::HTTPDownload(asio::any_io_executor ex) : executor_(std::move(ex)) {}

asio::awaitable<tl::expected<void, std::error_code>>
HTTPDownload::fetch(const std::string& url,
                    const std::filesystem::path& destination,
                    std::chrono::milliseconds timeout) {
  auto parsed = parse_http_url(url);
  if (!parsed) {
    co_return tl::unexpected(parsed.error());
  }

  tcp::resolver resolver(executor_);
  auto [resolve_ec, endpoints] = co_await resolver.async_resolve(
    parsed->host,
    std::to_string(parsed->port),
    asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  if (resolve_ec) {
    co_return tl::unexpected(make_error_code(errc::connect_failed));
  }

  tcp::socket socket(executor_);
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
    "GET " + parsed->path + " HTTP/1.1\r\n"
    "Host: " + parsed->host + ":" + std::to_string(parsed->port) + "\r\n"
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
  const auto headers = std::string_view(buffered).substr(0, header_end + 2);
  if (!success_status(headers)) {
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  auto expected_length = content_length_from(headers);
  if (!expected_length) {
    co_return tl::unexpected(expected_length.error());
  }

  const auto body_start = header_end + 4;
  std::vector<std::byte> body;
  body.reserve(*expected_length);
  for (std::size_t i = body_start; i < buffered.size() && body.size() < *expected_length; ++i) {
    body.push_back(static_cast<std::byte>(static_cast<unsigned char>(buffered[i])));
  }

  while (body.size() < *expected_length) {
    std::array<char, 4096> chunk{};
    auto need = std::min<std::size_t>(chunk.size(), *expected_length - body.size());
    auto [read_ec, n] = co_await asio::async_read(
      socket,
      asio::buffer(chunk.data(), need),
      asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
    if (read_ec) {
      co_return tl::unexpected(make_error_code(
        read_ec == asio::error::operation_aborted ? errc::timed_out : errc::connection_closed));
    }
    for (std::size_t i = 0; i < n; ++i) {
      body.push_back(static_cast<std::byte>(static_cast<unsigned char>(chunk[i])));
    }
  }

  std::ofstream out(destination, std::ios::binary | std::ios::trunc);
  if (!out) {
    co_return tl::unexpected(make_error_code(errc::io_error));
  }
  out.write(reinterpret_cast<const char*>(body.data()), static_cast<std::streamsize>(body.size()));
  if (!out) {
    co_return tl::unexpected(make_error_code(errc::io_error));
  }
  co_return tl::expected<void, std::error_code>{};
}

} // namespace ed2k::infra
