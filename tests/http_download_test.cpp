#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <gtest/gtest.h>

#include "ed2k/infra/http_download.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/util/error.hpp"
#include "mock_peer.hpp"

using namespace ed2k;
using namespace ed2k::infra;
using namespace ed2k::net;
using namespace std::chrono_literals;

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

namespace {
std::filesystem::path tls_fixture(std::string_view name) {
  return std::filesystem::path(ED2K_TEST_FIXTURE_DIR) / "tls" / name;
}

class LocalTLSServer {
 public:
  explicit LocalTLSServer(asio::io_context& context, std::string host = "localhost")
      : acceptor_(context),
        context_(asio::ssl::context::tls_server) {
    tcp::resolver resolver(context);
    const auto endpoints = resolver.resolve(host, "0");
    const auto endpoint = endpoints.begin()->endpoint();
    acceptor_.open(endpoint.protocol());
    acceptor_.bind(endpoint);
    acceptor_.listen();
    context_.use_certificate_chain_file(tls_fixture("server.crt").string());
    context_.use_private_key_file(tls_fixture("server.key").string(),
                                  asio::ssl::context::pem);
  }

  std::uint16_t port() const { return acceptor_.local_endpoint().port(); }

  void serve(std::function<asio::awaitable<void>(asio::ssl::stream<tcp::socket>&)> handler) {
    asio::co_spawn(
      acceptor_.get_executor(),
      [this, handler = std::move(handler)]() -> asio::awaitable<void> {
        auto [accept_ec, socket] =
          co_await acceptor_.async_accept(asio::as_tuple(asio::use_awaitable));
        if (accept_ec) {
          co_return;
        }

        asio::ssl::stream<tcp::socket> stream(std::move(socket), context_);
        auto [handshake_ec] = co_await stream.async_handshake(
          asio::ssl::stream_base::server, asio::as_tuple(asio::use_awaitable));
        if (handshake_ec) {
          co_return;
        }
        co_await handler(stream);
      },
      asio::detached);
  }

 private:
  tcp::acceptor acceptor_;
  asio::ssl::context context_;
};

template <class F>
void run_coro(IoRuntime& rt, F&& body) {
  bool done = false;
  asio::co_spawn(rt.context(),
    [&]() -> asio::awaitable<void> {
      co_await body();
      done = true;
      rt.stop();
      co_return;
    },
    [&](std::exception_ptr e) {
      rt.stop();
      if (e) std::rethrow_exception(e);
    });
  rt.run();
  rt.restart();
  EXPECT_TRUE(done);
}

std::string read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

asio::awaitable<std::string> read_request_target(tcp::socket& socket) {
  asio::streambuf buffer;
  auto [ec, n] = co_await asio::async_read_until(
    socket, buffer, "\r\n\r\n", asio::as_tuple(asio::use_awaitable));
  (void)n;
  if (ec) {
    co_return std::string{};
  }

  const std::string request(asio::buffers_begin(buffer.data()), asio::buffers_end(buffer.data()));
  const auto method_end = request.find(' ');
  const auto target_end = request.find(' ', method_end == std::string::npos ? 0 : method_end + 1);
  if (method_end == std::string::npos || target_end == std::string::npos) {
    co_return std::string{};
  }
  co_return request.substr(method_end + 1, target_end - method_end - 1);
}

asio::awaitable<std::string>
read_tls_request_target(asio::ssl::stream<tcp::socket>& stream) {
  asio::streambuf buffer;
  auto [ec, n] = co_await asio::async_read_until(
    stream, buffer, "\r\n\r\n", asio::as_tuple(asio::use_awaitable));
  (void)n;
  if (ec) {
    co_return std::string{};
  }

  const std::string request(asio::buffers_begin(buffer.data()), asio::buffers_end(buffer.data()));
  const auto method_end = request.find(' ');
  const auto target_end = request.find(' ', method_end == std::string::npos ? 0 : method_end + 1);
  if (method_end == std::string::npos || target_end == std::string::npos) {
    co_return std::string{};
  }
  co_return request.substr(method_end + 1, target_end - method_end - 1);
}
} // namespace

TEST(HTTPDownload, FetchWritesResponseBodyToFile) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  std::string request;

  server.serve([&](tcp::socket s) -> asio::awaitable<void> {
    asio::streambuf buf;
    auto [r_ec, r_n] = co_await asio::async_read_until(s, buf, "\r\n\r\n", asio::as_tuple(asio::use_awaitable));
    if (r_ec) co_return;
    request.assign(asio::buffers_begin(buf.data()), asio::buffers_end(buf.data()));
    const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    co_await asio::async_write(s, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
    co_return;
  });

  const auto path = std::filesystem::temp_directory_path() / "ed2k_http_download_test.bin";
  std::filesystem::remove(path);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch("http://127.0.0.1:" + std::to_string(server.port()) + "/server.met", path, 2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  EXPECT_NE(request.find("GET /server.met HTTP/1.1"), std::string::npos);
  EXPECT_EQ(read_text(path), "hello");
  std::filesystem::remove(path);
}

TEST(HTTPDownload, FetchesHttpsWithTrustedTestCa) {
  IoRuntime rt;
  LocalTLSServer server(rt.context());
  std::string target;

  server.serve([&](asio::ssl::stream<tcp::socket>& stream) -> asio::awaitable<void> {
    target = co_await read_tls_request_target(stream);
    const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    co_await asio::async_write(
      stream, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  const auto path = std::filesystem::temp_directory_path() / "ed2k_https_download_test.bin";
  std::filesystem::remove(path);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor(), HTTPDownloadOptions{tls_fixture("ca.crt")});
    auto r = co_await http.fetch(
      "https://localhost:" + std::to_string(server.port()) + "/server.met", path, 2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
  });

  EXPECT_EQ(target, "/server.met");
  EXPECT_EQ(read_text(path), "hello");
  std::filesystem::remove(path);
}

TEST(HTTPDownload, FollowsHttpRedirectToHttps) {
  IoRuntime rt;
  ed2k::test::MockPeer http_server(rt.context());
  LocalTLSServer tls_server(rt.context());
  std::string http_target;
  std::string https_target;

  http_server.serve([&](tcp::socket socket) -> asio::awaitable<void> {
    http_target = co_await read_request_target(socket);
    const std::string response =
      "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: https://localhost:" +
      std::to_string(tls_server.port()) + "/secure.met\r\n\r\n";
    co_await asio::async_write(
      socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });
  tls_server.serve([&](asio::ssl::stream<tcp::socket>& stream) -> asio::awaitable<void> {
    https_target = co_await read_tls_request_target(stream);
    const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    co_await asio::async_write(
      stream, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  const auto path =
    std::filesystem::temp_directory_path() / "ed2k_http_to_https_redirect_test.bin";
  std::filesystem::remove(path);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor(), HTTPDownloadOptions{tls_fixture("ca.crt")});
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(http_server.port()) + "/redirect",
      path,
      2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
  });

  EXPECT_EQ(http_target, "/redirect");
  EXPECT_EQ(https_target, "/secure.met");
  EXPECT_EQ(read_text(path), "hello");
  std::filesystem::remove(path);
}

TEST(HTTPDownload, RejectsUntrustedCertificate) {
  IoRuntime rt;
  LocalTLSServer server(rt.context());
  server.serve([](asio::ssl::stream<tcp::socket>&) -> asio::awaitable<void> {
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "https://localhost:" + std::to_string(server.port()) + "/server.met",
      std::filesystem::temp_directory_path() / "ed2k_https_untrusted_test.bin",
      2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::tls_error));
    }
  });
}

TEST(HTTPDownload, RejectsHostnameMismatch) {
  IoRuntime rt;
  LocalTLSServer server(rt.context(), "127.0.0.1");
  server.serve([](asio::ssl::stream<tcp::socket>&) -> asio::awaitable<void> {
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor(), HTTPDownloadOptions{tls_fixture("ca.crt")});
    auto r = co_await http.fetch(
      "https://127.0.0.1:" + std::to_string(server.port()) + "/server.met",
      std::filesystem::temp_directory_path() / "ed2k_https_hostname_test.bin",
      2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::tls_error));
    }
  });
}

TEST(HTTPDownload, SendsRequestedHostnameAsSni) {
  IoRuntime rt;
  LocalTLSServer server(rt.context());
  std::string server_name;

  server.serve([&](asio::ssl::stream<tcp::socket>& stream) -> asio::awaitable<void> {
    if (const char* name = SSL_get_servername(stream.native_handle(), TLSEXT_NAMETYPE_host_name)) {
      server_name = name;
    }
    EXPECT_EQ(co_await read_tls_request_target(stream), "/server.met");
    const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    co_await asio::async_write(
      stream, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  const auto path = std::filesystem::temp_directory_path() / "ed2k_https_sni_test.bin";
  std::filesystem::remove(path);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor(), HTTPDownloadOptions{tls_fixture("ca.crt")});
    auto r = co_await http.fetch(
      "https://localhost:" + std::to_string(server.port()) + "/server.met", path, 2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
  });

  EXPECT_EQ(server_name, "localhost");
  std::filesystem::remove(path);
}

TEST(HTTPDownload, UsesSingleDeadlineAcrossRedirects) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  std::size_t requests = 0;

  auto handler = [&](tcp::socket socket) -> asio::awaitable<void> {
    const auto target = co_await read_request_target(socket);
    const bool first = requests++ == 0;
    EXPECT_EQ(target, first ? "/old" : "/new");
    asio::steady_timer timer(rt.context());
    timer.expires_after(90ms);
    co_await timer.async_wait(asio::use_awaitable);
    const std::string response = first
      ? "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: /new\r\n\r\n"
      : "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    co_await asio::async_write(
      socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  };
  server.serve(handler);
  server.serve(handler);

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/old",
      std::filesystem::temp_directory_path() / "ed2k_http_deadline_test.bin",
      150ms);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::timed_out));
    }
  });
}

TEST(HTTPDownload, FollowsRelativeRedirect) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  std::vector<std::string> targets;

  auto handler = [&](tcp::socket socket) -> asio::awaitable<void> {
    const auto target = co_await read_request_target(socket);
    targets.push_back(target);
    const std::string response = target == "/old"
      ? "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: new\r\n\r\n"
      : "HTTP/1.1 206 Partial Content\r\nContent-Length: 5\r\n\r\nhello";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  };
  server.serve(handler);
  server.serve(handler);

  const auto path = std::filesystem::temp_directory_path() / "ed2k_http_redirect_test.bin";
  std::filesystem::remove(path);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/old", path, 2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  EXPECT_EQ(targets, (std::vector<std::string>{"/old", "/new"}));
  EXPECT_EQ(read_text(path), "hello");
  std::filesystem::remove(path);
}

TEST(HTTPDownload, FollowsAbsoluteHttpRedirect) {
  IoRuntime rt;
  ed2k::test::MockPeer first(rt.context());
  ed2k::test::MockPeer second(rt.context());
  std::string first_target;
  std::string second_target;

  first.serve([&](tcp::socket socket) -> asio::awaitable<void> {
    first_target = co_await read_request_target(socket);
    const std::string response =
      "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: http://127.0.0.1:" +
      std::to_string(second.port()) + "/new\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });
  second.serve([&](tcp::socket socket) -> asio::awaitable<void> {
    second_target = co_await read_request_target(socket);
    const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  const auto path = std::filesystem::temp_directory_path() / "ed2k_http_absolute_redirect_test.bin";
  std::filesystem::remove(path);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(first.port()) + "/old", path, 2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  EXPECT_EQ(first_target, "/old");
  EXPECT_EQ(second_target, "/new");
  std::filesystem::remove(path);
}

TEST(HTTPDownload, RejectsUnsupportedAbsoluteSchemeWithoutSlashes) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());

  server.serve([&](tcp::socket socket) -> asio::awaitable<void> {
    EXPECT_EQ(co_await read_request_target(socket), "/old");
    const std::string response =
      "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: ftp:next\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/old",
      std::filesystem::temp_directory_path() / "ed2k_http_unsupported_redirect_test.bin",
      2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::malformed_link));
    }
    co_return;
  });
}

TEST(HTTPDownload, TreatsHttpLikeTextInRelativeTarget) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  std::vector<std::string> targets;

  auto handler = [&](tcp::socket socket) -> asio::awaitable<void> {
    const auto target = co_await read_request_target(socket);
    targets.push_back(target);
    const std::string response = target == "/dir/old"
      ? "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: next/http://x\r\n\r\n"
      : "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  };
  server.serve(handler);
  server.serve(handler);

  const auto path = std::filesystem::temp_directory_path() / "ed2k_http_scheme_text_test.bin";
  std::filesystem::remove(path);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/dir/old", path, 2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  EXPECT_EQ(targets, (std::vector<std::string>{"/dir/old", "/dir/next/http://x"}));
  std::filesystem::remove(path);
}

TEST(HTTPDownload, FollowsSchemeRelativeRedirect) {
  IoRuntime rt;
  ed2k::test::MockPeer first(rt.context());
  ed2k::test::MockPeer second(rt.context());
  std::string first_target;
  std::string second_target;

  first.serve([&](tcp::socket socket) -> asio::awaitable<void> {
    first_target = co_await read_request_target(socket);
    const std::string response =
      "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: //127.0.0.1:" +
      std::to_string(second.port()) + "/new\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });
  second.serve([&](tcp::socket socket) -> asio::awaitable<void> {
    second_target = co_await read_request_target(socket);
    const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  const auto path = std::filesystem::temp_directory_path() / "ed2k_http_scheme_relative_test.bin";
  std::filesystem::remove(path);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(first.port()) + "/old", path, 2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  EXPECT_EQ(first_target, "/old");
  EXPECT_EQ(second_target, "/new");
  std::filesystem::remove(path);
}

TEST(HTTPDownload, FollowsRedirectWithoutDownloadingDeclaredBody) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  std::vector<std::string> targets;

  auto handler = [&](tcp::socket socket) -> asio::awaitable<void> {
    const auto target = co_await read_request_target(socket);
    targets.push_back(target);
    const std::string response = target == "/old"
      ? "HTTP/1.1 302 Found\r\nContent-Length: 268435457\r\nLocation: /new\r\n\r\n"
      : "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  };
  server.serve(handler);
  server.serve(handler);

  const auto path = std::filesystem::temp_directory_path() / "ed2k_http_redirect_body_test.bin";
  std::filesystem::remove(path);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/old", path, 2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  EXPECT_EQ(targets, (std::vector<std::string>{"/old", "/new"}));
  std::filesystem::remove(path);
}

TEST(HTTPDownload, RejectsOversizedSuccessBody) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());

  server.serve([&](tcp::socket socket) -> asio::awaitable<void> {
    EXPECT_EQ(co_await read_request_target(socket), "/large");
    const std::string response =
      "HTTP/1.1 200 OK\r\nContent-Length: 268435457\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/large",
      std::filesystem::temp_directory_path() / "ed2k_http_large_body_test.bin",
      2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::server_protocol_error));
    }
    co_return;
  });
}

TEST(HTTPDownload, RejectsOversizedResponseHeader) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());

  server.serve([&](tcp::socket socket) -> asio::awaitable<void> {
    EXPECT_EQ(co_await read_request_target(socket), "/large-header");
    const std::string response =
      "HTTP/1.1 200 OK\r\nX-Fill: " + std::string(65536, 'a') +
      "\r\nContent-Length: 0\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/large-header",
      std::filesystem::temp_directory_path() / "ed2k_http_large_header_test.bin",
      2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::server_protocol_error));
    }
    co_return;
  });
}

TEST(HTTPDownload, PreservesRepeatedSlashesInPathRelativeRedirect) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  std::vector<std::string> targets;

  auto handler = [&](tcp::socket socket) -> asio::awaitable<void> {
    const auto target = co_await read_request_target(socket);
    targets.push_back(target);
    const std::string response = target == "/dir/old"
      ? "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: next//file\r\n\r\n"
      : "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  };
  server.serve(handler);
  server.serve(handler);

  const auto path = std::filesystem::temp_directory_path() / "ed2k_http_path_redirect_test.bin";
  std::filesystem::remove(path);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/dir/old",
      path,
      2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  EXPECT_EQ(targets, (std::vector<std::string>{"/dir/old", "/dir/next//file"}));
  std::filesystem::remove(path);
}

TEST(HTTPDownload, RejectsRedirectLoopAfterFiveHops) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  std::vector<std::string> targets;

  auto handler = [&](tcp::socket socket) -> asio::awaitable<void> {
    const auto target = co_await read_request_target(socket);
    targets.push_back(target);
    const auto hop = targets.size() - 1;
    const std::string location = hop < 5 ? "/hop-" + std::to_string(hop + 1) : "/hop-0";
    const std::string response =
      "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: " + location + "\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  };
  for (int i = 0; i < 6; ++i) {
    server.serve(handler);
  }

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/hop-0",
      std::filesystem::temp_directory_path() / "ed2k_http_loop_test.bin",
      2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::server_protocol_error));
    }
    co_return;
  });

  EXPECT_EQ(targets, (std::vector<std::string>{
                       "/hop-0", "/hop-1", "/hop-2", "/hop-3", "/hop-4", "/hop-5"}));
}

TEST(HTTPDownload, RejectsShortRedirectLoop) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  std::vector<std::string> targets;

  auto handler = [&](tcp::socket socket) -> asio::awaitable<void> {
    const auto target = co_await read_request_target(socket);
    targets.push_back(target);
    const std::string location = target == "/loop-a" ? "/loop-b" : "/loop-a";
    const std::string response =
      "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: " + location + "\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  };
  server.serve(handler);
  server.serve(handler);

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/loop-a",
      std::filesystem::temp_directory_path() / "ed2k_http_short_loop_test.bin",
      2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::server_protocol_error));
    }
    co_return;
  });

  EXPECT_EQ(targets, (std::vector<std::string>{"/loop-a", "/loop-b"}));
}

TEST(HTTPDownload, PreservesInitialRequestTarget) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  std::string target;

  server.serve([&](tcp::socket socket) -> asio::awaitable<void> {
    target = co_await read_request_target(socket);
    const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  const auto path = std::filesystem::temp_directory_path() / "ed2k_http_raw_target_test.bin";
  std::filesystem::remove(path);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/a//b/../c?x=1",
      path,
      2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  EXPECT_EQ(target, "/a//b/../c?x=1");
  std::filesystem::remove(path);
}

TEST(HTTPDownload, DoesNotConflateDistinctRedirectTargets) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  std::vector<std::string> targets;

  auto handler = [&](tcp::socket socket) -> asio::awaitable<void> {
    const auto target = co_await read_request_target(socket);
    targets.push_back(target);
    const std::string response = target == "/a//b"
      ? "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: /a/b\r\n\r\n"
      : "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  };
  server.serve(handler);
  server.serve(handler);

  const auto path = std::filesystem::temp_directory_path() / "ed2k_http_distinct_target_test.bin";
  std::filesystem::remove(path);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/a//b",
      path,
      2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  EXPECT_EQ(targets, (std::vector<std::string>{"/a//b", "/a/b"}));
  std::filesystem::remove(path);
}

TEST(HTTPDownload, PreservesRootRelativeRedirectTarget) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  std::vector<std::string> targets;

  auto handler = [&](tcp::socket socket) -> asio::awaitable<void> {
    const auto target = co_await read_request_target(socket);
    targets.push_back(target);
    const std::string response = target == "/old"
      ? "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: /r//x/../y\r\n\r\n"
      : "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  };
  server.serve(handler);
  server.serve(handler);

  const auto path = std::filesystem::temp_directory_path() / "ed2k_http_root_redirect_test.bin";
  std::filesystem::remove(path);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/old",
      path,
      2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
    co_return;
  });

  EXPECT_EQ(targets, (std::vector<std::string>{"/old", "/r//x/../y"}));
  std::filesystem::remove(path);
}

TEST(HTTPDownload, RejectsRedirectWithoutLocation) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  std::string target;

  server.serve([&](tcp::socket socket) -> asio::awaitable<void> {
    target = co_await read_request_target(socket);
    const std::string response = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n";
    co_await asio::async_write(socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/missing-location",
      std::filesystem::temp_directory_path() / "ed2k_http_missing_location_test.bin",
      2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::server_protocol_error));
    }
    co_return;
  });

  EXPECT_EQ(target, "/missing-location");
}

TEST(HTTPDownload, RejectsUnsupportedScheme) {
  IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "ftp://example.invalid/file",
      std::filesystem::temp_directory_path() / "unused",
      100ms);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::malformed_link));
    }
    co_return;
  });
}
