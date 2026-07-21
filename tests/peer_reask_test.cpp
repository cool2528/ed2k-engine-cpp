#include <gtest/gtest.h>
#include <chrono>
#include <exception>
#include <variant>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/udp.hpp>
#include "ed2k/peer/peer_reask.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/peer/c2c_opcodes.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/udp_socket.hpp"
#include "ed2k/net/packet.hpp"
using namespace ed2k; using namespace ed2k::peer; using namespace ed2k::net;
namespace asio = boost::asio;
using udp = asio::ip::udp;
using namespace std::chrono_literals;

// 把测试协程跑到完成；完成即 stop() 让挂起操作收场；异常上抛为测试失败。
// 协程体内只能用 EXPECT_*，不能用 ASSERT_*（其 return; 在协程里非法）。
template <class F> static void run_coro(IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(),
    [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart();
  EXPECT_TRUE(done);
}

// UdpSocket 绑定的是 0.0.0.0；local_endpoint() 的地址字段不能直接当目标地址用，
// 只取端口号，配合显式 loopback 地址构造出可用于发送的对端 endpoint（同 udp_socket_test.cpp）。
static udp::endpoint loop_ep(const UdpSocket& s){
  return udp::endpoint(asio::ip::address_v4::loopback(), s.local_endpoint().port());
}

static FileHash test_hash(){
  return *FileHash::from_hex("00112233445566778899aabbccddeeff");
}

TEST(PeerReask, ReaskAckRoundTripReturnsRank){
  IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpSocket downloader(rt.executor()), source(rt.executor());
    const auto h = test_hash();
    const auto source_ep = loop_ep(source);

    // 模拟源：收到 REASKFILEPING 后回 REASKACK(rank=7)。
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      auto rp = co_await source.recv_from(1s);
      EXPECT_TRUE(rp.has_value());
      if(!rp) co_return;
      EXPECT_EQ(rp->first.protocol, proto::eMule);
      EXPECT_EQ(rp->first.opcode, op::REASKFILEPING);
      auto decoded = decode_reask_file_ping(rp->first.payload);
      EXPECT_TRUE(decoded.has_value());
      if(decoded) EXPECT_EQ(*decoded, h);
      Packet ack; ack.protocol=proto::eMule; ack.opcode=op::REASKACK; ack.payload=encode_reask_ack(7);
      auto sr = co_await source.send_to(rp->second, ack);
      EXPECT_TRUE(sr.has_value());
      co_return;
    }, asio::detached);

    auto result = co_await reask_source(downloader, source_ep, h, 1s);
    EXPECT_TRUE(std::holds_alternative<ReaskRank>(result));
    if(!std::holds_alternative<ReaskRank>(result)) co_return;
    EXPECT_EQ(std::get<ReaskRank>(result).rank, 7u);
    co_return;
  });
}

TEST(PeerReask, QueueFullRecognized){
  IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpSocket downloader(rt.executor()), source(rt.executor());
    const auto h = test_hash();
    const auto source_ep = loop_ep(source);

    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      auto rp = co_await source.recv_from(1s);
      EXPECT_TRUE(rp.has_value());
      if(!rp) co_return;
      Packet full; full.protocol=proto::eMule; full.opcode=op::QUEUEFULL; // 空 payload
      auto sr = co_await source.send_to(rp->second, full);
      EXPECT_TRUE(sr.has_value());
      co_return;
    }, asio::detached);

    auto result = co_await reask_source(downloader, source_ep, h, 1s);
    EXPECT_TRUE(std::holds_alternative<ReaskQueueFull>(result));
    co_return;
  });
}

TEST(PeerReask, TimesOutWhenSourceDoesNotRespond){
  IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpSocket downloader(rt.executor()), source(rt.executor());
    const auto h = test_hash();
    const auto source_ep = loop_ep(source);
    // source 存在但从不响应。
    auto result = co_await reask_source(downloader, source_ep, h, 100ms);
    EXPECT_TRUE(std::holds_alternative<ReaskUnavailable>(result));
    co_return;
  });
}

TEST(PeerReask, IgnoresResponseFromWrongSender){
  IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void>{
    UdpSocket downloader(rt.executor()), real_source(rt.executor()), impostor(rt.executor());
    const auto h = test_hash();
    const auto downloader_ep = loop_ep(downloader);
    const auto real_source_ep = loop_ep(real_source);

    // 冒充者抢先发一个看起来有效的 REASKACK，但它不是被询问的 source——必须被丢弃。
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      Packet fake; fake.protocol=proto::eMule; fake.opcode=op::REASKACK; fake.payload=encode_reask_ack(999);
      auto sr = co_await impostor.send_to(downloader_ep, fake);
      EXPECT_TRUE(sr.has_value());
      co_return;
    }, asio::detached);

    // 真正的源稍后才回应真实 rank。
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      auto rp = co_await real_source.recv_from(1s);
      EXPECT_TRUE(rp.has_value());
      if(!rp) co_return;
      Packet ack; ack.protocol=proto::eMule; ack.opcode=op::REASKACK; ack.payload=encode_reask_ack(7);
      auto sr = co_await real_source.send_to(rp->second, ack);
      EXPECT_TRUE(sr.has_value());
      co_return;
    }, asio::detached);

    auto result = co_await reask_source(downloader, real_source_ep, h, 1s);
    EXPECT_TRUE(std::holds_alternative<ReaskRank>(result));
    if(!std::holds_alternative<ReaskRank>(result)) co_return;
    EXPECT_EQ(std::get<ReaskRank>(result).rank, 7u);
    co_return;
  });
}
