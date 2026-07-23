#include <gtest/gtest.h>
#include <chrono>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/buffer.hpp>
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/encrypted_stream_socket.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/infra/ip_filter.hpp"
#include "ed2k/peer/inbound_listener.hpp"
#include "ed2k/util/error.hpp"
using namespace ed2k; using namespace ed2k::peer;
namespace asio = boost::asio; using tcp = asio::ip::tcp;
using namespace std::chrono_literals;
template <class F> static void run_coro(ed2k::net::IoRuntime& rt, F&& body){
  bool done=false;
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{ co_await body(); done=true; co_return; },
    [&](std::exception_ptr e){ rt.stop(); if(e) std::rethrow_exception(e); });
  rt.run(); rt.restart(); EXPECT_TRUE(done);
}
TEST(InboundListener, AcceptsInboundConnection){
  ed2k::net::IoRuntime rt;
  InboundListener lst(rt.executor(), 0);   // ephemeral port
  EXPECT_NE(lst.local_port(), 0u);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    // 同时发起 accept 与一个出站连接
    tcp::socket client(rt.executor());
    tcp::endpoint ep(asio::ip::make_address_v4("127.0.0.1"), lst.local_port());
    auto [ec] = co_await client.async_connect(ep, asio::as_tuple(asio::use_awaitable));
    EXPECT_FALSE(ec);
    auto acc = co_await lst.accept(2000ms);
    EXPECT_TRUE(acc.has_value()) << (acc? "" : acc.error().message());
    if(!acc) co_return;
    EXPECT_TRUE(acc->is_open());
    // 回声验证: client 写一字节, accept 侧读到
    std::byte out{0xAB};
    auto [we,wn] = co_await asio::async_write(client, asio::buffer(&out,1), asio::as_tuple(asio::use_awaitable));(void)we;(void)wn;
    std::byte in{};
    auto [re,rn] = co_await asio::async_read(*acc, asio::buffer(&in,1), asio::as_tuple(asio::use_awaitable));(void)re;(void)rn;
    EXPECT_EQ(in, std::byte(0xAB));
    co_return;
  });
}
TEST(InboundListener, AcceptTimesOut){
  ed2k::net::IoRuntime rt;
  InboundListener lst(rt.executor(), 0);
  run_coro(rt, [&]() -> asio::awaitable<void>{
    auto acc = co_await lst.accept(200ms);
    EXPECT_FALSE(acc.has_value());
    if(!acc) EXPECT_EQ(acc.error(), make_error_code(errc::timed_out));
    co_return;
  });
}

static UserHash listener_hash() {
  return *UserHash::from_hex("0123456789abcdeffedcba9876543210");
}
static HelloInfo listener_hello(std::string nickname) {
  HelloInfo hello;
  hello.nickname = std::move(nickname);
  hello.version = 0x3c;
  hello.port = 4662;
  hello.user_hash = listener_hash();
  return hello;
}

TEST(InboundListener, RequiredObfuscationRejectsPlainMarker) {
  ed2k::net::IoRuntime rt;
  InboundListener listener(rt.executor(), 0);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    tcp::socket client(rt.executor());
    co_await client.async_connect(
        tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), listener.local_port()),
        asio::use_awaitable);
    const std::byte marker{ed2k::net::proto::eDonkey};
    co_await asio::async_write(client, asio::buffer(&marker, 1), asio::use_awaitable);
    auto accepted = co_await listener.accept_peer(
        listener_hash(), ObfuscationPolicy::required, 500ms);
    EXPECT_FALSE(accepted.has_value());
    co_return;
  });
}

TEST(InboundListener, RejectsFilteredPeerBeforeReadingMarker) {
  ed2k::net::IoRuntime rt;
  InboundListener listener(rt.executor(), 0);
  auto filter = std::make_shared<ed2k::infra::IPFilter>();
  filter->add(ed2k::infra::IPRange{
      .start = *IPv4::from_dotted("127.0.0.1"),
      .end = *IPv4::from_dotted("127.0.0.1"),
      .level = 200,
      .name = "loopback",
  });
  run_coro(rt, [&]() -> asio::awaitable<void> {
    tcp::socket client(rt.executor());
    co_await client.async_connect(
        tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), listener.local_port()),
        asio::use_awaitable);
    auto accepted = co_await listener.accept_peer(
        listener_hash(), ObfuscationPolicy::preferred, 500ms, filter, 127);
    EXPECT_FALSE(accepted.has_value());
    if (!accepted) EXPECT_EQ(accepted.error(), make_error_code(errc::ip_filtered));
    co_return;
  });
}

TEST(InboundListener, PreferredObfuscationAcceptsPlainAndPreservesMarker) {
  ed2k::net::IoRuntime rt;
  InboundListener listener(rt.executor(), 0);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    tcp::socket client(rt.executor());
    co_await client.async_connect(
        tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), listener.local_port()),
        asio::use_awaitable);
    ed2k::net::Packet hello_packet;
    hello_packet.protocol = ed2k::net::proto::eDonkey;
    hello_packet.opcode = op::HELLO;
    hello_packet.payload = encode_hello_packet(listener_hello("plain-client"));
    auto frame = ed2k::net::encode_frame(hello_packet);
    co_await asio::async_write(client, asio::buffer(frame), asio::use_awaitable);

    auto accepted = co_await listener.accept_peer(
        listener_hash(), ObfuscationPolicy::preferred, 500ms);
    EXPECT_TRUE(accepted.has_value()) << (accepted ? "" : accepted.error().message());
    if (!accepted) co_return;
    EXPECT_FALSE(accepted->encrypted());
    auto hello = co_await accepted->handshake_acceptor(listener_hello("server"), 500ms);
    EXPECT_TRUE(hello.has_value()) << (hello ? "" : hello.error().message());
    if (hello) EXPECT_EQ(hello->nickname, "plain-client");
    co_return;
  });
}

TEST(InboundListener, PreferredObfuscationAcceptsEncryptedStream) {
  ed2k::net::IoRuntime rt;
  InboundListener listener(rt.executor(), 0);
  boost::asio::experimental::channel<void(boost::system::error_code, bool)> completed(rt.executor(), 1);
  asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void> {
    ed2k::net::EncryptedStreamSocket client(rt.executor());
    auto connected = co_await client.connect(*IPv4::from_dotted("127.0.0.1"),
                                             listener.local_port(), 500ms);
    if (!connected) co_return;
    auto negotiated = co_await client.handshake_initiator(listener_hash(), 500ms);
    if (!negotiated) co_return;
    ed2k::net::Packet hello_packet;
    hello_packet.protocol = ed2k::net::proto::eDonkey;
    hello_packet.opcode = op::HELLO;
    hello_packet.payload = encode_hello_packet(listener_hello("encrypted-client"));
    if (!(co_await client.send(hello_packet))) co_return;
    auto answer = co_await client.recv(500ms);
    completed.try_send(boost::system::error_code{}, answer && answer->opcode == op::HELLOANSWER);
    co_return;
  }, asio::detached);
  run_coro(rt, [&]() -> asio::awaitable<void> {
    auto accepted = co_await listener.accept_peer(
        listener_hash(), ObfuscationPolicy::preferred, 500ms);
    EXPECT_TRUE(accepted.has_value()) << (accepted ? "" : accepted.error().message());
    if (!accepted) co_return;
    EXPECT_TRUE(accepted->encrypted());
    auto hello = co_await accepted->handshake_acceptor(listener_hello("server"), 500ms);
    EXPECT_TRUE(hello.has_value()) << (hello ? "" : hello.error().message());
    if (hello) EXPECT_EQ(hello->nickname, "encrypted-client");
    EXPECT_TRUE(co_await completed.async_receive(asio::use_awaitable));
    co_return;
  });
}

// D1: 两个 LowID 源"并发回调"场景的最小复现——两个 worker 各自等待各自源的入站连接
// (accept_peer 的 expected_ip 参数, 见 inbound_listener.hpp 注释)。用两个不同的 loopback
// 源地址(127.0.0.21/127.0.0.22, 通过 connect 前显式 bind 本地地址实现)模拟"两个不同 LowID
// 源"; 用各自 HELLO 里的昵称核验"谁真的连上了谁"。
//
// 两条连接在两个 worker 都尚未开始等待之前就已经在 OS accept 队列里排好(bob 先连, alice 后连
// ——TCP 三次握手不需要我方调用 accept() 就能在内核侧完成排队, 见 dial_back 的"已连接确认"
// 信号), 而两个 worker 的注册顺序反过来是 alice 先、bob 后——用 OS accept 队列固有的 FIFO
// 语义(而非依赖 asio 内部对多个并发 async_accept 调度顺序这种平台相关细节)确定性地构造
// "先注册的等待者本应对应后到达的连接"这种错位, 直接命中"先到先得"会 crossed 的场景。
//
// 修复前(先到先得, 逐 worker 各自独立 accept()): 先注册的 alice-worker 直接 accept() 到
// 队列里第一条(bob 的)连接——错配; 修复后: 每个 worker 只认领与自己 expected_ip 精确匹配
// 的连接, 与到达顺序/注册顺序都无关。
TEST(InboundListener, RoutesConcurrentLowIdCallbacksByExpectedIp) {
  ed2k::net::IoRuntime rt;
  InboundListener listener(rt.executor(), 0);
  const auto alice_ip = *IPv4::from_dotted("127.0.0.21");
  const auto bob_ip = *IPv4::from_dotted("127.0.0.22");

  struct Outcome { bool ok = false; std::string nickname; };
  using ResultCh = asio::experimental::channel<void(boost::system::error_code, Outcome)>;
  using ConnectedCh = asio::experimental::channel<void(boost::system::error_code)>;

  run_coro(rt, [&]() -> asio::awaitable<void> {
    // 模拟一次"LowID 源回拨": 把源端本地地址显式 bind 到 from_ip 后 connect 并发送 HELLO,
    // 随后通过 connected 信号告知编排协程"这条连接已经在 OS accept 队列里排好、HELLO 也已
    // 发出"; 之后继续存活(阻塞读)到 accept_peer 一侧读完 HELLO 并回 HELLOANSWER 为止,
    // 避免协程提前退出关闭 socket 打断对端读取。
    auto dial_back = [&](IPv4 from_ip, std::string nickname,
                         std::shared_ptr<ConnectedCh> connected) -> asio::awaitable<void> {
      tcp::socket client(rt.executor());
      client.open(tcp::v4());
      client.bind(tcp::endpoint(asio::ip::make_address_v4(from_ip.host()), 0));
      auto [cec] = co_await client.async_connect(
          tcp::endpoint(asio::ip::make_address_v4("127.0.0.1"), listener.local_port()),
          asio::as_tuple(asio::use_awaitable));
      if (cec) { connected->try_send(cec); co_return; }
      ed2k::net::Packet hello_packet;
      hello_packet.protocol = ed2k::net::proto::eDonkey;
      hello_packet.opcode = op::HELLO;
      hello_packet.payload = encode_hello_packet(listener_hello(nickname));
      auto frame = ed2k::net::encode_frame(hello_packet);
      co_await asio::async_write(client, asio::buffer(frame), asio::use_awaitable);
      connected->try_send(boost::system::error_code{});
      std::byte trash{};
      co_await client.async_receive(asio::buffer(&trash, 1), asio::as_tuple(asio::use_awaitable));
      co_return;
    };
    // 一个 worker 的完整生命周期: 按 expected_ip 等待入站连接, 再走 HELLO 握手读回对端昵称。
    auto wait_and_identify = [&](IPv4 expected) -> asio::awaitable<Outcome> {
      auto accepted = co_await listener.accept_peer(
          listener_hash(), ObfuscationPolicy::preferred, 2000ms, nullptr, 127, expected);
      if (!accepted) co_return Outcome{};
      auto hello = co_await accepted->handshake_acceptor(listener_hello("server"), 500ms);
      if (!hello) co_return Outcome{};
      co_return Outcome{true, hello->nickname};
    };

    // 阶段一: 先把两条连接都建立好并排进 OS accept 队列(bob 先, alice 后), 此时两个 worker
    // 都还没开始等待。
    auto bob_connected = std::make_shared<ConnectedCh>(rt.executor(), 1);
    auto alice_connected = std::make_shared<ConnectedCh>(rt.executor(), 1);
    asio::co_spawn(rt.context(), dial_back(bob_ip, "bob", bob_connected), asio::detached);
    co_await bob_connected->async_receive(asio::use_awaitable);
    asio::co_spawn(rt.context(), dial_back(alice_ip, "alice", alice_connected), asio::detached);
    co_await alice_connected->async_receive(asio::use_awaitable);

    // 阶段二: 两个 worker 开始等待——注册顺序 alice 先、bob 后, 与阶段一"bob 先到"的队列
    // 顺序故意相反。
    ResultCh alice_result(rt.executor(), 1), bob_result(rt.executor(), 1);
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void> {
      auto r = co_await wait_and_identify(alice_ip);
      co_await alice_result.async_send(boost::system::error_code{}, r, asio::use_awaitable);
    }, asio::detached);
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void> {
      auto r = co_await wait_and_identify(bob_ip);
      co_await bob_result.async_send(boost::system::error_code{}, r, asio::use_awaitable);
    }, asio::detached);

    auto [aec, aout] = co_await alice_result.async_receive(asio::as_tuple(asio::use_awaitable));
    auto [bec, bout] = co_await bob_result.async_receive(asio::as_tuple(asio::use_awaitable));
    (void)aec; (void)bec;

    // 注意: 协程体内不能用 ASSERT_*(宏内含裸 return, 与 co_await 函数的协程约束冲突,
    // 见本文件其它测试的既有写法), 改用 EXPECT_* + 手动 guard。
    EXPECT_TRUE(aout.ok);
    EXPECT_TRUE(bout.ok);
    if (!aout.ok || !bout.ok) co_return;
    EXPECT_EQ(aout.nickname, "alice") << "alice-worker(expected_ip=127.0.0.21) 拿到了错误的对端";
    EXPECT_EQ(bout.nickname, "bob") << "bob-worker(expected_ip=127.0.0.22) 拿到了错误的对端";
    co_return;
  });
}
