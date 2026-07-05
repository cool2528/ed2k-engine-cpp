#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <string>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <gtest/gtest.h>

#include "ed2k/infra/http_download.hpp"
#include "ed2k/net/runtime.hpp"
#include "mock_peer.hpp"

using namespace ed2k;
using namespace ed2k::infra;
using namespace ed2k::net;
using namespace std::chrono_literals;

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

namespace {
template <class F>
void run_coro(IoRuntime& rt, F&& body) {
  bool done = false;
  asio::co_spawn(rt.context(),
    [&]() -> asio::awaitable<void> {
      co_await body();
      done = true;
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

TEST(HTTPDownload, RejectsHttpsUntilSslSupportExists) {
  IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch("https://example.invalid/file", std::filesystem::temp_directory_path() / "unused", 100ms);
    EXPECT_FALSE(r.has_value());
    co_return;
  });
}
