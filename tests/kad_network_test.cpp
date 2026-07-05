#include <gtest/gtest.h>

#include <chrono>
#include <exception>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include "ed2k/kad/messages.hpp"
#include "ed2k/kad/network.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/udp_socket.hpp"
#include "ed2k/util/error.hpp"

using namespace ed2k;
using namespace ed2k::kad;
namespace asio = boost::asio;
using udp = asio::ip::udp;
using namespace std::chrono_literals;

namespace {
template <class F>
void run_coro(net::IoRuntime& rt, F&& body) {
  bool done = false;
  asio::co_spawn(
      rt.context(),
      [&]() -> asio::awaitable<void> {
        co_await body();
        done = true;
        co_return;
      },
      [&](std::exception_ptr e) {
        rt.stop();
        if (e) {
          std::rethrow_exception(e);
        }
      });
  rt.run();
  rt.restart();
  EXPECT_TRUE(done);
}

KadID kid(const char* hex) {
  return *KadID::from_hex(hex);
}

IPv4 loopback_ip() {
  return *IPv4::from_dotted("127.0.0.1");
}

KadNetworkOptions options(const char* id_hex, std::uint16_t tcp_port) {
  return KadNetworkOptions{
      .id = kid(id_hex),
      .ip = loopback_ip(),
      .tcp_port = tcp_port,
      .version = kad2_version,
  };
}

udp::endpoint endpoint_for(const KadNetwork& network) {
  return udp::endpoint(asio::ip::address_v4::loopback(), network.local_endpoint().port());
}

Contact contact(const char* id_hex, std::uint16_t udp_port, std::uint16_t tcp_port) {
  return Contact{
      .id = kid(id_hex),
      .ip = loopback_ip(),
      .udp_port = udp_port,
      .tcp_port = tcp_port,
      .version = kad2_version,
  };
}

asio::awaitable<void> serve_n(KadNetwork& network, int count) {
  for (int i = 0; i < count; ++i) {
    (void)co_await network.serve_once(500ms);
  }
  co_return;
}
} // namespace

TEST(KadNetwork, HelloRoundTripUpdatesRoutingTables) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork a(rt.executor(), options("00000000000000000000000000000001", 5501));
    KadNetwork b(rt.executor(), options("00000000000000000000000000000002", 5502));

    asio::co_spawn(rt.context(), serve_n(b, 1), asio::detached);

    auto remote = co_await a.send_hello(endpoint_for(b), 1s);
    EXPECT_TRUE(remote.has_value());
    if (!remote) {
      co_return;
    }

    EXPECT_EQ(remote->id, b.self_contact().id);
    EXPECT_EQ(remote->tcp_port, 5502);
    EXPECT_NE(a.routing_table().find(b.self_contact().id), nullptr);
    EXPECT_NE(b.routing_table().find(a.self_contact().id), nullptr);
    co_return;
  });
}

TEST(KadNetwork, ReqReturnsClosestContactsAndRejectsWrongReceiverCheck) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork requester(rt.executor(), options("00000000000000000000000000000001", 5601));
    KadNetwork responder(rt.executor(), options("00000000000000000000000000000002", 5602));
    auto close_contact = contact("00000000000000000000000000000003", 5603, 6603);
    auto far_contact = contact("80000000000000000000000000000000", 5604, 6604);
    EXPECT_TRUE(responder.routing_table().add_or_update(close_contact));
    EXPECT_TRUE(responder.routing_table().add_or_update(far_contact));

    asio::co_spawn(rt.context(), serve_n(responder, 1), asio::detached);
    auto contacts = co_await requester.request_closest(responder.self_contact(),
                                                       kid("00000000000000000000000000000000"), 1, 1s);
    EXPECT_TRUE(contacts.has_value());
    if (!contacts) {
      co_return;
    }
    EXPECT_EQ(contacts->size(), 1u);
    if (contacts->empty()) {
      co_return;
    }
    EXPECT_EQ((*contacts)[0].id, close_contact.id);
    EXPECT_NE(requester.routing_table().find(close_contact.id), nullptr);

    net::UdpSocket probe(rt.executor());
    asio::co_spawn(rt.context(), serve_n(responder, 1), asio::detached);
    auto bad_req = encode_kad2_req(kid("00000000000000000000000000000000"),
                                   kid("ffffffffffffffffffffffffffffffff"), 1);
    auto sent = co_await probe.send_to(endpoint_for(responder), bad_req);
    EXPECT_TRUE(sent.has_value());
    if (!sent) {
      co_return;
    }
    auto response = co_await probe.recv_from(150ms);
    EXPECT_FALSE(response.has_value());
    if (!response) {
      EXPECT_EQ(response.error(), make_error_code(errc::timed_out));
    }
    probe.close();
    co_return;
  });
}

TEST(KadNetwork, BootstrapFromSeedLearnsReturnedContacts) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork joining(rt.executor(), options("00000000000000000000000000000001", 5701));
    KadNetwork seed(rt.executor(), options("00000000000000000000000000000002", 5702));
    KadNetwork known(rt.executor(), options("00000000000000000000000000000003", 5703));
    EXPECT_TRUE(seed.routing_table().add_or_update(known.self_contact()));

    asio::co_spawn(rt.context(), serve_n(seed, 2), asio::detached);
    std::vector<Contact> seeds{seed.self_contact()};
    auto bootstrapped = co_await joining.bootstrap(seeds, 1s);
    EXPECT_TRUE(bootstrapped.has_value());
    if (!bootstrapped) {
      co_return;
    }

    EXPECT_NE(joining.routing_table().find(seed.self_contact().id), nullptr);
    EXPECT_NE(joining.routing_table().find(known.self_contact().id), nullptr);
    co_return;
  });
}
