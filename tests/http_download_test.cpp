#include <atomic>
#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
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

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include "ed2k/infra/http_download.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/util/error.hpp"
#include "infra/http_download_internal.hpp"
#include "infra/tls_trust_store.hpp"
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
 private:
  struct State {
    explicit State(asio::io_context& io_context, const std::string& host)
        : acceptor(io_context), context(asio::ssl::context::tls_server) {
      tcp::resolver resolver(io_context);
      const auto endpoints = resolver.resolve(host, "0");
      const auto endpoint = endpoints.begin()->endpoint();
      acceptor.open(endpoint.protocol());
      acceptor.bind(endpoint);
      acceptor.listen();
      context.use_certificate_chain_file(tls_fixture("server.crt").string());
      context.use_private_key_file(tls_fixture("server.key").string(),
                                   asio::ssl::context::pem);
    }

    tcp::acceptor acceptor;
    asio::ssl::context context;
  };

 public:
  explicit LocalTLSServer(asio::io_context& context, std::string host = "localhost")
      : state_(std::make_shared<State>(context, host)) {}

  std::uint16_t port() const { return state_->acceptor.local_endpoint().port(); }

  void serve(std::function<asio::awaitable<void>(asio::ssl::stream<tcp::socket>&)> handler) {
    auto state = state_;
    const auto executor = state->acceptor.get_executor();
    asio::co_spawn(
      executor,
      [state = std::move(state), handler = std::move(handler)]() -> asio::awaitable<void> {
        auto [accept_ec, socket] =
          co_await state->acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
        if (accept_ec) {
          co_return;
        }

        asio::ssl::stream<tcp::socket> stream(std::move(socket), state->context);
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
  std::shared_ptr<State> state_;
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

void write_text(const std::filesystem::path& path, std::string_view text) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  ASSERT_TRUE(out);
  out.write(text.data(), static_cast<std::streamsize>(text.size()));
  ASSERT_TRUE(out);
}

std::size_t sibling_artifact_count(const std::filesystem::path& destination) {
  std::size_t count = 0;
  for (const auto& entry : std::filesystem::directory_iterator(destination.parent_path())) {
    const auto name = entry.path().filename().string();
    if (name.starts_with(".ed2k-http-") &&
        (name.ends_with(".tmp") || name.ends_with(".bak"))) {
      ++count;
    }
  }
  return count;
}

class ScopedTestDirectory {
 public:
  ScopedTestDirectory() {
    static std::atomic<std::uint64_t> next_id{0};
    path_ = std::filesystem::temp_directory_path() /
      ("ed2k_http_test_" +
       std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" +
       std::to_string(next_id.fetch_add(1, std::memory_order_relaxed)));
    std::filesystem::create_directory(path_);
  }

  ~ScopedTestDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  std::filesystem::path path(std::string_view name) const { return path_ / name; }

 private:
  std::filesystem::path path_;
};

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

TEST(HTTPDownload, PreservesExistingDestinationWhenBodyIsTruncated) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  server.serve([](tcp::socket socket) -> asio::awaitable<void> {
    EXPECT_FALSE((co_await read_request_target(socket)).empty());
    const std::string response =
      "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort";
    co_await asio::async_write(
      socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  const auto path =
    std::filesystem::temp_directory_path() / "ed2k_http_truncated_preserves_test.bin";
  std::filesystem::remove(path);
  write_text(path, "old-data");

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/server.met", path, 2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::connection_closed));
    }
  });

  EXPECT_EQ(read_text(path), "old-data");
  EXPECT_EQ(sibling_artifact_count(path), 0u);
  std::filesystem::remove(path);
}

TEST(HTTPDownload, PreservesExistingDestinationWhenTlsValidationFails) {
  IoRuntime rt;
  LocalTLSServer server(rt.context());
  server.serve([](asio::ssl::stream<tcp::socket>&) -> asio::awaitable<void> {
    co_return;
  });

  const auto path =
    std::filesystem::temp_directory_path() / "ed2k_https_failure_preserves_test.bin";
  std::filesystem::remove(path);
  write_text(path, "old-data");

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "https://localhost:" + std::to_string(server.port()) + "/server.met", path, 2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::tls_error));
    }
  });

  EXPECT_EQ(read_text(path), "old-data");
  EXPECT_EQ(sibling_artifact_count(path), 0u);
  std::filesystem::remove(path);
}

TEST(HTTPDownload, PreservesExistingDestinationForNonSuccessResponse) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  server.serve([](tcp::socket socket) -> asio::awaitable<void> {
    EXPECT_FALSE((co_await read_request_target(socket)).empty());
    const std::string response =
      "HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\nerror";
    co_await asio::async_write(
      socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  const auto path =
    std::filesystem::temp_directory_path() / "ed2k_http_non_success_preserves_test.bin";
  std::filesystem::remove(path);
  write_text(path, "old-data");

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/server.met", path, 2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::server_protocol_error));
    }
  });

  EXPECT_EQ(read_text(path), "old-data");
  EXPECT_EQ(sibling_artifact_count(path), 0u);
  std::filesystem::remove(path);
}

TEST(HTTPDownload, ReplacesExistingDestinationOnlyAfterCompleteSuccessfulBody) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  ScopedTestDirectory directory;
  const auto path = directory.path("destination.bin");
  const auto old_alias = directory.path("old-alias.bin");
  write_text(path, "old-data");
  std::error_code link_error;
  std::filesystem::create_hard_link(path, old_alias, link_error);
  if (link_error) {
    GTEST_SKIP() << "hard links unavailable: " << link_error.message();
  }

  server.serve([&](tcp::socket socket) -> asio::awaitable<void> {
    EXPECT_FALSE((co_await read_request_target(socket)).empty());
    const std::string first =
      "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnew-";
    co_await asio::async_write(
      socket, asio::buffer(first), asio::as_tuple(asio::use_awaitable));
    EXPECT_EQ(read_text(path), "old-data");
    const std::string second = "data";
    co_await asio::async_write(
      socket, asio::buffer(second), asio::as_tuple(asio::use_awaitable));
  });

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/server.met", path, 2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
  });

  EXPECT_EQ(read_text(path), "new-data");
  EXPECT_EQ(read_text(old_alias), "old-data");
  EXPECT_EQ(sibling_artifact_count(path), 0u);
}

TEST(HTTPDownload, RejectsDirectoryDestinationWithoutReplacingIt) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  server.serve([](tcp::socket socket) -> asio::awaitable<void> {
    EXPECT_FALSE((co_await read_request_target(socket)).empty());
    const std::string response =
      "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnew-data";
    co_await asio::async_write(
      socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  const auto path =
    std::filesystem::temp_directory_path() / "ed2k_http_directory_destination_test";
  std::filesystem::remove_all(path);
  ASSERT_TRUE(std::filesystem::create_directory(path));

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/server.met", path, 2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::io_error));
    }
  });

  EXPECT_TRUE(std::filesystem::is_directory(path));
  EXPECT_EQ(sibling_artifact_count(path), 0u);
  std::filesystem::remove_all(path);
}

TEST(HTTPDownload, ReportsIoErrorWhenDestinationParentIsMissing) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  server.serve([](tcp::socket socket) -> asio::awaitable<void> {
    EXPECT_FALSE((co_await read_request_target(socket)).empty());
    const std::string response =
      "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnew-data";
    co_await asio::async_write(
      socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  ScopedTestDirectory directory;
  const auto missing_parent = directory.path("missing");
  const auto path = missing_parent / "destination.bin";
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/server.met", path, 2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::io_error));
    }
  });

  EXPECT_FALSE(std::filesystem::exists(missing_parent));
}

#ifdef _WIN32
TEST(HTTPDownload, WritesUnicodeDestinationAtomically) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  server.serve([](tcp::socket socket) -> asio::awaitable<void> {
    EXPECT_FALSE((co_await read_request_target(socket)).empty());
    const std::string response =
      "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnew-data";
    co_await asio::async_write(
      socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  ScopedTestDirectory directory;
  const auto path = directory.path("") / std::filesystem::path(L"\u4e0b\u8f7d.bin");
  write_text(path, "old-data");
  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/server.met", path, 2s);
    EXPECT_TRUE(r.has_value()) << (r ? "" : r.error().message());
  });

  EXPECT_EQ(read_text(path), "new-data");
  EXPECT_EQ(sibling_artifact_count(path), 0u);
}

ed2k::infra::detail::WindowsNativeFileOps simulated_replace_ops(
  std::uint32_t replace_error,
  bool* move_called = nullptr,
  bool allow_restore = true) {
  return {
    [replace_error](const std::filesystem::path& destination,
                    const std::filesystem::path& temporary,
                    const std::filesystem::path& backup) {
      if (replace_error == ERROR_UNABLE_TO_MOVE_REPLACEMENT_2) {
        std::filesystem::rename(destination, backup);
      }
      return false;
    },
    [move_called, allow_restore](const std::filesystem::path& from,
                                 const std::filesystem::path& to) {
      if (move_called) {
        *move_called = true;
      }
      if (!allow_restore) {
        return false;
      }
      std::error_code error;
      std::filesystem::rename(from, to, error);
      return !error;
    },
    [](const std::filesystem::path& path) {
      std::error_code error;
      const bool removed = std::filesystem::remove(path, error);
      return removed && !error;
    },
    [replace_error] { return replace_error; },
  };
}

void expect_original_names_failure_reconciled(std::uint32_t replace_error) {
  ScopedTestDirectory directory;
  const auto destination = directory.path("destination.bin");
  const auto temporary = directory.path("temporary.bin");
  const auto backup = directory.path("backup.bin");
  write_text(destination, "old-data");
  write_text(temporary, "new-data");

  const auto result = ed2k::infra::detail::replace_existing_file_windows(
    temporary, destination, backup, simulated_replace_ops(replace_error));

  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(read_text(destination), "old-data");
  EXPECT_FALSE(std::filesystem::exists(temporary));
  EXPECT_FALSE(std::filesystem::exists(backup));
}

TEST(HTTPDownload, ReconcilesUnableToRemoveReplacedState) {
  expect_original_names_failure_reconciled(ERROR_UNABLE_TO_REMOVE_REPLACED);
}

TEST(HTTPDownload, ReconcilesUnableToMoveReplacementState) {
  expect_original_names_failure_reconciled(ERROR_UNABLE_TO_MOVE_REPLACEMENT);
}

TEST(HTTPDownload, RejectsEmptyBackupBeforeNativeReplacement) {
  ScopedTestDirectory directory;
  const auto destination = directory.path("destination.bin");
  const auto temporary = directory.path("temporary.bin");
  write_text(destination, "old-data");
  write_text(temporary, "new-data");
  bool replace_called = false;
  auto ops = simulated_replace_ops(ERROR_UNABLE_TO_MOVE_REPLACEMENT);
  ops.replace_file = [&replace_called](const std::filesystem::path&,
                                      const std::filesystem::path&,
                                      const std::filesystem::path&) {
    replace_called = true;
    return false;
  };

  const auto result = ed2k::infra::detail::replace_existing_file_windows(
    temporary, destination, {}, ops);

  EXPECT_FALSE(result.has_value());
  EXPECT_FALSE(replace_called);
  EXPECT_EQ(read_text(destination), "old-data");
  EXPECT_EQ(read_text(temporary), "new-data");
}

TEST(HTTPDownload, PreservesUnexpectedBackupOnNativeNameCollision) {
  ScopedTestDirectory directory;
  const auto destination = directory.path("destination.bin");
  const auto temporary = directory.path("temporary.bin");
  const auto backup = directory.path("backup.bin");
  write_text(destination, "old-data");
  write_text(temporary, "new-data");
  write_text(backup, "unrelated-data");

  const auto result = ed2k::infra::detail::replace_existing_file_windows(
    temporary, destination, backup, simulated_replace_ops(ERROR_ALREADY_EXISTS));

  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(read_text(destination), "old-data");
  EXPECT_FALSE(std::filesystem::exists(temporary));
  EXPECT_EQ(read_text(backup), "unrelated-data");
}

TEST(HTTPDownload, RestoresBackupAfterUnableToMoveReplacement2) {
  ScopedTestDirectory directory;
  const auto destination = directory.path("destination.bin");
  const auto temporary = directory.path("temporary.bin");
  const auto backup = directory.path("backup.bin");
  write_text(destination, "old-data");
  write_text(temporary, "new-data");
  bool move_called = false;

  const auto result = ed2k::infra::detail::replace_existing_file_windows(
    temporary,
    destination,
    backup,
    simulated_replace_ops(ERROR_UNABLE_TO_MOVE_REPLACEMENT_2, &move_called));

  EXPECT_FALSE(result.has_value());
  EXPECT_TRUE(move_called);
  EXPECT_EQ(read_text(destination), "old-data");
  EXPECT_FALSE(std::filesystem::exists(temporary));
  EXPECT_FALSE(std::filesystem::exists(backup));
}

TEST(HTTPDownload, PreservesBackupAndCleansTempWhenBackupRestoreFails) {
  ScopedTestDirectory directory;
  const auto destination = directory.path("destination.bin");
  const auto temporary = directory.path("temporary.bin");
  const auto backup = directory.path("backup.bin");
  write_text(destination, "old-data");
  write_text(temporary, "new-data");
  bool move_called = false;

  const auto result = ed2k::infra::detail::replace_existing_file_windows(
    temporary,
    destination,
    backup,
    simulated_replace_ops(
      ERROR_UNABLE_TO_MOVE_REPLACEMENT_2, &move_called, false));

  EXPECT_FALSE(result.has_value());
  EXPECT_TRUE(move_called);
  EXPECT_FALSE(std::filesystem::exists(destination));
  EXPECT_FALSE(std::filesystem::exists(temporary));
  EXPECT_EQ(read_text(backup), "old-data");
}

TEST(HTTPDownload, RemovesBackupAfterCompletedNativeReplacement) {
  ScopedTestDirectory directory;
  const auto destination = directory.path("destination.bin");
  const auto temporary = directory.path("temporary.bin");
  const auto backup = directory.path("backup.bin");
  write_text(destination, "old-data");
  write_text(temporary, "new-data");
  auto ops = simulated_replace_ops(0);
  bool flush_called = false;
  ops.replace_file = [](const std::filesystem::path& destination,
                        const std::filesystem::path& temporary,
                        const std::filesystem::path& backup) {
    std::filesystem::rename(destination, backup);
    std::filesystem::rename(temporary, destination);
    return true;
  };
  ops.flush_file = [&flush_called](const std::filesystem::path&) {
    flush_called = true;
    return true;
  };

  const auto result = ed2k::infra::detail::replace_existing_file_windows(
    temporary, destination, backup, ops);

  EXPECT_TRUE(result.has_value()) << (result ? "" : result.error().message());
  EXPECT_TRUE(flush_called);
  EXPECT_EQ(read_text(destination), "new-data");
  EXPECT_FALSE(std::filesystem::exists(temporary));
  EXPECT_FALSE(std::filesystem::exists(backup));
}

TEST(HTTPDownload, PreservesBackupWhenInstalledDestinationFlushFails) {
  ScopedTestDirectory directory;
  const auto destination = directory.path("destination.bin");
  const auto temporary = directory.path("temporary.bin");
  const auto backup = directory.path("backup.bin");
  write_text(destination, "old-data");
  write_text(temporary, "new-data");
  auto ops = simulated_replace_ops(0);
  ops.replace_file = [](const std::filesystem::path& destination,
                        const std::filesystem::path& temporary,
                        const std::filesystem::path& backup) {
    std::filesystem::rename(destination, backup);
    std::filesystem::rename(temporary, destination);
    return true;
  };
  ops.flush_file = [](const std::filesystem::path&) { return false; };

  const auto result = ed2k::infra::detail::replace_existing_file_windows(
    temporary, destination, backup, ops);

  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(read_text(destination), "new-data");
  EXPECT_EQ(read_text(backup), "old-data");
  EXPECT_FALSE(std::filesystem::exists(temporary));
}

TEST(HTTPDownload, ReportsBackupCleanupFailureAfterCompletedReplacement) {
  ScopedTestDirectory directory;
  const auto destination = directory.path("destination.bin");
  const auto temporary = directory.path("temporary.bin");
  const auto backup = directory.path("backup.bin");
  write_text(destination, "old-data");
  write_text(temporary, "new-data");
  auto ops = simulated_replace_ops(0);
  ops.replace_file = [](const std::filesystem::path& destination,
                        const std::filesystem::path& temporary,
                        const std::filesystem::path& backup) {
    std::filesystem::rename(destination, backup);
    std::filesystem::rename(temporary, destination);
    return true;
  };
  ops.remove_file = [](const std::filesystem::path&) { return false; };

  const auto result = ed2k::infra::detail::replace_existing_file_windows(
    temporary, destination, backup, ops);

  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(read_text(destination), "new-data");
  EXPECT_EQ(read_text(backup), "old-data");
  EXPECT_FALSE(std::filesystem::exists(temporary));
}

TEST(HTTPDownload, PreservesExistingDestinationWhenAtomicReplaceFails) {
  IoRuntime rt;
  ed2k::test::MockPeer server(rt.context());
  server.serve([](tcp::socket socket) -> asio::awaitable<void> {
    EXPECT_FALSE((co_await read_request_target(socket)).empty());
    const std::string response =
      "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnew-data";
    co_await asio::async_write(
      socket, asio::buffer(response), asio::as_tuple(asio::use_awaitable));
  });

  const auto path =
    std::filesystem::temp_directory_path() / "ed2k_http_replace_failure_test.bin";
  std::filesystem::remove(path);
  write_text(path, "old-data");
  const HANDLE locked = CreateFileW(path.c_str(),
                                    GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
  ASSERT_NE(locked, INVALID_HANDLE_VALUE);

  run_coro(rt, [&]() -> asio::awaitable<void> {
    HTTPDownload http(rt.executor());
    auto r = co_await http.fetch(
      "http://127.0.0.1:" + std::to_string(server.port()) + "/server.met", path, 2s);
    EXPECT_FALSE(r.has_value());
    if (!r) {
      EXPECT_EQ(r.error(), make_error_code(errc::io_error));
    }
  });

  EXPECT_EQ(read_text(path), "old-data");
  EXPECT_EQ(sibling_artifact_count(path), 0u);
  EXPECT_TRUE(CloseHandle(locked));
  std::filesystem::remove(path);
}
#endif

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

TEST(HTTPDownload, ReportsMissingAdditionalCaFile) {
  auto context = create_tls_client_context(tls_fixture("missing-ca.crt"));
  ASSERT_FALSE(context.has_value());
  EXPECT_EQ(context.error(), make_error_code(errc::file_not_found));
}

TEST(HTTPDownload, ReportsNonRegularAdditionalCaAsIoError) {
  auto context = create_tls_client_context(tls_fixture(""));
  ASSERT_FALSE(context.has_value());
  EXPECT_EQ(context.error(), make_error_code(errc::io_error));
}

TEST(HTTPDownload, ReportsMalformedAdditionalCaAsTlsError) {
  auto context = create_tls_client_context(tls_fixture("server.key"));
  ASSERT_FALSE(context.has_value());
  EXPECT_EQ(context.error(), make_error_code(errc::tls_error));
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

  EXPECT_EQ(requests, 2u);
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
