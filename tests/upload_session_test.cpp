#include <gtest/gtest.h>
#include <array>
#include <chrono>
#include <exception>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include "ed2k/net/runtime.hpp"
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/share/known_file.hpp"
#include "ed2k/share/upload_session.hpp"
#include "mock_peer.hpp"

using namespace ed2k;
using namespace ed2k::peer;
using namespace ed2k::share;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

template <class F> static void run_coro(ed2k::net::IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(),
    [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart();
  EXPECT_TRUE(done);
}

static HelloInfo hello(std::string name){
  HelloInfo h;
  h.nickname = std::move(name);
  h.version = 0x3C;
  h.port = 4662;
  h.user_hash = *UserHash::from_hex("0123456789abcdeffedcba9876543210");
  return h;
}

TEST(UploadSession, AnswersFilenameStatusAndHashset){
  ed2k::net::IoRuntime rt;
  KnownFileDB db;
  KnownFile f;
  f.hash = *FileHash::from_hex("00112233445566778899aabbccddeeff");
  f.aich_root = *AICHHash::from_base32("A2IU2MP7W3D2Q3E2VJPHADW6T5S4HJE3");
  f.name = "shared.bin";
  f.size = 20000000;
  f.part_hashes = {
    *PartHash::from_hex("11111111111111111111111111111111"),
    *PartHash::from_hex("22222222222222222222222222222222")
  };
  db.add(f);

  ed2k::test::MockPeer peer(rt.context());
  peer.serve([&](tcp::socket s) -> asio::awaitable<void>{
    UploadSession session(std::move(s), db, hello("server"));
    (void)co_await session.run(2s);
    co_return;
  });

  run_coro(rt, [&]() -> asio::awaitable<void>{
    C2CConnection c(rt.executor());
    auto cr = co_await c.connect(*IPv4::from_dotted("127.0.0.1"), peer.port(), 2s);
    EXPECT_TRUE(cr.has_value()); if(!cr) co_return;
    auto hs = co_await c.handshake(hello("client"), 2s);
    EXPECT_TRUE(hs.has_value()); if(!hs) co_return;

    auto name = co_await c.request_filename(f.hash, 2s);
    EXPECT_TRUE(name.has_value()); if(!name) co_return;
    EXPECT_EQ(*name, "shared.bin");

    auto status = co_await c.request_file(f.hash, 2s);
    EXPECT_TRUE(status.has_value()); if(!status) co_return;
    EXPECT_TRUE(status->parts.empty());

    auto hashes = co_await c.request_hashset(f.hash, 2s);
    EXPECT_TRUE(hashes.has_value()); if(!hashes) co_return;
    EXPECT_EQ(*hashes, f.part_hashes);
    c.close();
    co_return;
  });
}
