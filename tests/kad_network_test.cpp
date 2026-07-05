#include <gtest/gtest.h>

#include <chrono>
#include <exception>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include "ed2k/codec/tag.hpp"
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

codec::Tag string_tag(std::uint8_t name_id, std::string value) {
  codec::Tag tag;
  tag.name_str = std::string(1, static_cast<char>(name_id));
  tag.value = std::move(value);
  return tag;
}

codec::Tag int_tag(std::uint8_t name_id, std::uint64_t value) {
  codec::Tag tag;
  tag.name_str = std::string(1, static_cast<char>(name_id));
  tag.value = value;
  return tag;
}

KadSearchEntry file_entry(const char* file_hex, std::string name, std::uint64_t size) {
  return KadSearchEntry{
      .answer_id = kid(file_hex),
      .tags = {string_tag(tag::filename, std::move(name)), int_tag(tag::file_size, size)},
  };
}

KadSearchEntry source_entry(const char* source_hex, std::uint16_t tcp_port, std::uint16_t udp_port,
                            std::uint64_t size) {
  return KadSearchEntry{
      .answer_id = kid(source_hex),
      .tags = {int_tag(tag::source_type, 1), int_tag(tag::source_port, tcp_port),
               int_tag(tag::source_udp_port, udp_port), int_tag(tag::file_size, size)},
  };
}

KadSearchEntry note_entry(const char* source_hex, std::string description, std::uint64_t size) {
  return KadSearchEntry{
      .answer_id = kid(source_hex),
      .tags = {string_tag(tag::description, std::move(description)), int_tag(tag::file_rating, 4),
               int_tag(tag::file_size, size)},
  };
}

asio::awaitable<void> serve_n(KadNetwork& network, int count) {
  for (int i = 0; i < count; ++i) {
    (void)co_await network.serve_once(500ms);
  }
  co_return;
}

asio::awaitable<void> serve_legacy_bootstrap(net::UdpSocket& socket, Contact self, Contact known) {
  auto bootstrap = co_await socket.recv_from(500ms);
  EXPECT_TRUE(bootstrap.has_value());
  if (!bootstrap) {
    co_return;
  }
  EXPECT_EQ(bootstrap->first.protocol, kad_protocol);
  EXPECT_EQ(bootstrap->first.opcode, opcode::kad2_bootstrap_req);

  auto hello = co_await socket.recv_from(500ms);
  EXPECT_TRUE(hello.has_value());
  if (!hello) {
    co_return;
  }
  EXPECT_EQ(hello->first.protocol, kad_protocol);
  EXPECT_EQ(hello->first.opcode, opcode::kad2_hello_req);

  auto sent_hello = co_await socket.send_to(hello->second, encode_kad2_hello_res(self));
  EXPECT_TRUE(sent_hello.has_value());
  if (!sent_hello) {
    co_return;
  }

  auto request = co_await socket.recv_from(500ms);
  EXPECT_TRUE(request.has_value());
  if (!request) {
    co_return;
  }
  auto decoded = decode_kad2_req(request->first);
  EXPECT_TRUE(decoded.has_value());
  if (!decoded) {
    co_return;
  }

  std::vector<Contact> contacts{known};
  auto sent_contacts = co_await socket.send_to(request->second, encode_kad2_res(decoded->target, contacts));
  EXPECT_TRUE(sent_contacts.has_value());
  co_return;
}

asio::awaitable<void> serve_closest_without_search_response(net::UdpSocket& socket, Contact known) {
  auto request = co_await socket.recv_from(1s);
  EXPECT_TRUE(request.has_value());
  if (!request) {
    co_return;
  }
  auto decoded = decode_kad2_req(request->first);
  EXPECT_TRUE(decoded.has_value());
  if (!decoded) {
    co_return;
  }

  std::vector<Contact> contacts{known};
  auto sent_contacts = co_await socket.send_to(request->second, encode_kad2_res(decoded->target, contacts));
  EXPECT_TRUE(sent_contacts.has_value());

  auto search = co_await socket.recv_from(1s);
  if (search) {
    EXPECT_EQ(search->first.protocol, kad_protocol);
    EXPECT_EQ(search->first.opcode, opcode::kad2_search_key_req);
  }
  co_return;
}

asio::awaitable<void> serve_far_closest_without_search_request(net::UdpSocket& socket, Contact known) {
  auto request = co_await socket.recv_from(1s);
  EXPECT_TRUE(request.has_value());
  if (!request) {
    co_return;
  }
  auto decoded = decode_kad2_req(request->first);
  EXPECT_TRUE(decoded.has_value());
  if (!decoded) {
    co_return;
  }

  std::vector<Contact> contacts{known};
  auto sent_contacts = co_await socket.send_to(request->second, encode_kad2_res(decoded->target, contacts));
  EXPECT_TRUE(sent_contacts.has_value());

  auto search = co_await socket.recv_from(100ms);
  EXPECT_FALSE(search.has_value());
  if (!search) {
    EXPECT_EQ(search.error(), make_error_code(errc::timed_out));
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

TEST(KadNetwork, BootstrapUsesKad2BootstrapRequestResponse) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork joining(rt.executor(), options("00000000000000000000000000000001", 5711));
    KadNetwork seed(rt.executor(), options("00000000000000000000000000000002", 5712));
    KadNetwork known(rt.executor(), options("00000000000000000000000000000003", 5713));
    EXPECT_TRUE(seed.routing_table().add_or_update(known.self_contact()));

    asio::co_spawn(rt.context(), serve_n(seed, 1), asio::detached);
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

TEST(KadNetwork, BootstrapFanoutReachesLaterLiveSeedWithinOneTimeoutWindow) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork joining(rt.executor(), options("00000000000000000000000000000001", 5721));
    KadNetwork live_seed(rt.executor(), options("00000000000000000000000000000002", 5722));
    KadNetwork known(rt.executor(), options("00000000000000000000000000000003", 5723));
    EXPECT_TRUE(live_seed.routing_table().add_or_update(known.self_contact()));

    std::vector<std::unique_ptr<net::UdpSocket>> silent_sockets;
    std::vector<Contact> seeds;
    for (int i = 0; i < 6; ++i) {
      silent_sockets.push_back(std::make_unique<net::UdpSocket>(rt.executor()));
      seeds.push_back(contact("10000000000000000000000000000000",
                              silent_sockets.back()->local_endpoint().port(),
                              static_cast<std::uint16_t>(6700 + i)));
    }
    seeds.push_back(live_seed.self_contact());

    asio::co_spawn(rt.context(), serve_n(live_seed, 1), asio::detached);
    const auto started = std::chrono::steady_clock::now();
    auto bootstrapped = co_await joining.bootstrap(seeds, 50ms);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_TRUE(bootstrapped.has_value());
    if (!bootstrapped) {
      co_return;
    }
    EXPECT_LT(elapsed, 250ms);
    EXPECT_NE(joining.routing_table().find(known.self_contact().id), nullptr);
    co_return;
  });
}

TEST(KadNetwork, BootstrapHelloFallbackFansOutToLaterLegacySeedWithinOneTimeoutWindow) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork joining(rt.executor(), options("00000000000000000000000000000001", 5731));
    net::UdpSocket legacy_socket(rt.executor());
    auto legacy_contact = contact("00000000000000000000000000000002",
                                  legacy_socket.local_endpoint().port(), 5732);
    legacy_contact.version = 5;
    auto known_contact = contact("00000000000000000000000000000003", 5733, 6733);
    known_contact.version = 5;

    std::vector<std::unique_ptr<net::UdpSocket>> silent_sockets;
    std::vector<Contact> seeds;
    for (int i = 0; i < 6; ++i) {
      silent_sockets.push_back(std::make_unique<net::UdpSocket>(rt.executor()));
      auto silent = contact("10000000000000000000000000000000",
                            silent_sockets.back()->local_endpoint().port(),
                            static_cast<std::uint16_t>(6800 + i));
      silent.version = 5;
      seeds.push_back(silent);
    }
    seeds.push_back(legacy_contact);

    asio::co_spawn(rt.context(), serve_legacy_bootstrap(legacy_socket, legacy_contact, known_contact),
                   asio::detached);
    const auto started = std::chrono::steady_clock::now();
    auto bootstrapped = co_await joining.bootstrap(seeds, 50ms);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_TRUE(bootstrapped.has_value());
    if (!bootstrapped) {
      co_return;
    }
    EXPECT_LT(elapsed, 250ms);
    EXPECT_NE(joining.routing_table().find(known_contact.id), nullptr);
    co_return;
  });
}

TEST(KadNetwork, PublishKeywordThenSearchFindsFile) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork publisher(rt.executor(), options("00000000000000000000000000000001", 5801));
    KadNetwork indexer(rt.executor(), options("00000000000000000000000000000002", 5802));
    KadNetwork searcher(rt.executor(), options("00000000000000000000000000000003", 5803));
    const auto key = kid("00000000000000000000000000000000");
    const std::vector<KadSearchEntry> files{
        file_entry("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "ubuntu.iso", 123456789ull)};

    asio::co_spawn(rt.context(), serve_n(indexer, 4), asio::detached);
    auto publish = co_await publisher.publish_keyword(indexer.self_contact(), key, files, 1s);
    EXPECT_TRUE(publish.has_value());
    if (!publish) {
      co_return;
    }

    std::vector<Contact> peers{indexer.self_contact()};
    auto results = co_await searcher.search_keyword(peers, key, 1s);
    EXPECT_TRUE(results.has_value());
    if (!results) {
      co_return;
    }
    EXPECT_EQ(results->size(), 1u);
    if (results->empty()) {
      co_return;
    }
    EXPECT_EQ((*results)[0].answer_id, files[0].answer_id);
    EXPECT_EQ(file_name((*results)[0]), "ubuntu.iso");
    EXPECT_EQ(file_size((*results)[0]), 123456789ull);
    co_return;
  });
}

TEST(KadNetwork, SearchKeywordIgnoresStaleBootstrapResponse) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork publisher(rt.executor(), options("00000000000000000000000000000001", 5804));
    KadNetwork indexer(rt.executor(), options("00000000000000000000000000000002", 5805));
    KadNetwork searcher(rt.executor(), options("00000000000000000000000000000003", 5806));
    const auto key = kid("00000000000000000000000000000000");
    const std::vector<KadSearchEntry> files{
        file_entry("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "ubuntu.iso", 123456789ull)};

    asio::co_spawn(rt.context(), serve_n(indexer, 4), asio::detached);
    auto publish = co_await publisher.publish_keyword(indexer.self_contact(), key, files, 1s);
    EXPECT_TRUE(publish.has_value());
    if (!publish) {
      co_return;
    }

    net::UdpSocket stale_sender(rt.executor());
    auto stale = co_await stale_sender.send_to(endpoint_for(searcher),
                                               encode_kad2_bootstrap_res(indexer.self_contact(), {}));
    EXPECT_TRUE(stale.has_value());
    if (!stale) {
      co_return;
    }

    std::vector<Contact> peers{indexer.self_contact()};
    auto results = co_await searcher.search_keyword(peers, key, 1s);
    EXPECT_TRUE(results.has_value()) << (results ? "" : results.error().message());
    if (!results) {
      co_return;
    }
    EXPECT_EQ(results->size(), 1u);
    if (results->empty()) {
      co_return;
    }
    EXPECT_EQ((*results)[0].answer_id, files[0].answer_id);
    stale_sender.close();
    co_return;
  });
}

TEST(KadNetwork, SearchKeywordExpandsWhenSeedHasNoIndexedResponse) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork publisher(rt.executor(), options("00000000000000000000000000000001", 5807));
    KadNetwork indexer(rt.executor(), options("00000000000000000000000000000002", 5808));
    KadNetwork searcher(rt.executor(), options("00000000000000000000000000000003", 5809));
    net::UdpSocket seed_socket(rt.executor());
    auto seed = contact("00000000000000000000000000000004",
                        seed_socket.local_endpoint().port(), 5810);
    seed.version = 5;
    const auto key = kid("00000000000000000000000000000000");
    const std::vector<KadSearchEntry> files{
        file_entry("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "ubuntu.iso", 123456789ull)};

    asio::co_spawn(rt.context(), serve_n(indexer, 4), asio::detached);
    auto publish = co_await publisher.publish_keyword(indexer.self_contact(), key, files, 1s);
    EXPECT_TRUE(publish.has_value());
    if (!publish) {
      co_return;
    }

    asio::co_spawn(rt.context(), serve_closest_without_search_response(seed_socket, indexer.self_contact()),
                   asio::detached);
    std::vector<Contact> peers{seed};
    auto results = co_await searcher.search_keyword(peers, key, 2s);
    EXPECT_TRUE(results.has_value()) << (results ? "" : results.error().message());
    if (!results) {
      co_return;
    }
    EXPECT_EQ(results->size(), 1u);
    if (results->empty()) {
      co_return;
    }
    EXPECT_EQ((*results)[0].answer_id, files[0].answer_id);
    seed_socket.close();
    co_return;
  });
}

TEST(KadNetwork, SearchKeywordDoesNotQueryFarSeedForIndexedValues) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork publisher(rt.executor(), options("00000000000000000000000000000001", 5815));
    KadNetwork indexer(rt.executor(), options("00000000000000000000000000000002", 5816));
    KadNetwork searcher(rt.executor(), options("00000000000000000000000000000003", 5817));
    net::UdpSocket seed_socket(rt.executor());
    auto seed = contact("40000000000000000000000000000000",
                        seed_socket.local_endpoint().port(), 5818);
    seed.version = 5;
    const auto key = kid("00000000000000000000000000000000");
    const std::vector<KadSearchEntry> files{
        file_entry("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "ubuntu.iso", 123456789ull)};

    asio::co_spawn(rt.context(), serve_n(indexer, 4), asio::detached);
    auto publish = co_await publisher.publish_keyword(indexer.self_contact(), key, files, 1s);
    EXPECT_TRUE(publish.has_value());
    if (!publish) {
      co_return;
    }

    asio::co_spawn(rt.context(), serve_far_closest_without_search_request(seed_socket, indexer.self_contact()),
                   asio::detached);
    std::vector<Contact> peers{seed};
    auto results = co_await searcher.search_keyword(peers, key, 2s);
    EXPECT_TRUE(results.has_value()) << (results ? "" : results.error().message());
    if (!results) {
      seed_socket.close();
      co_return;
    }
    EXPECT_EQ(results->size(), 1u);
    seed_socket.close();
    co_return;
  });
}

TEST(KadNetwork, SearchKeywordDiscoversIndexerThroughClosestNode) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork publisher(rt.executor(), options("00000000000000000000000000000001", 5811));
    KadNetwork seed(rt.executor(), options("00000000000000000000000000000002", 5812));
    KadNetwork indexer(rt.executor(), options("00000000000000000000000000000003", 5813));
    KadNetwork searcher(rt.executor(), options("00000000000000000000000000000004", 5814));
    const auto key = kid("00000000000000000000000000000000");
    const std::vector<KadSearchEntry> files{
        file_entry("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "ubuntu.iso", 123456789ull)};
    EXPECT_TRUE(seed.routing_table().add_or_update(indexer.self_contact()));

    asio::co_spawn(rt.context(), serve_n(indexer, 4), asio::detached);
    asio::co_spawn(rt.context(), serve_n(seed, 2), asio::detached);
    auto publish = co_await publisher.publish_keyword(indexer.self_contact(), key, files, 1s);
    EXPECT_TRUE(publish.has_value());
    if (!publish) {
      co_return;
    }

    std::vector<Contact> peers{seed.self_contact()};
    auto results = co_await searcher.search_keyword(peers, key, 1s);
    EXPECT_TRUE(results.has_value());
    if (!results) {
      co_return;
    }
    EXPECT_EQ(results->size(), 1u);
    if (results->empty()) {
      co_return;
    }
    EXPECT_EQ((*results)[0].answer_id, files[0].answer_id);
    EXPECT_NE(searcher.routing_table().find(indexer.self_contact().id), nullptr);
    co_return;
  });
}

TEST(KadNetwork, PublishSourceThenFindSourcesDeduplicates) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork publisher(rt.executor(), options("00000000000000000000000000000001", 5901));
    KadNetwork indexer(rt.executor(), options("00000000000000000000000000000002", 5902));
    KadNetwork searcher(rt.executor(), options("00000000000000000000000000000003", 5903));
    const auto file = kid("00000000000000000000000000000000");
    const auto first = source_entry("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 4662, 4665, 123456789ull);
    const auto updated = source_entry("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 4663, 4666, 123456789ull);

    asio::co_spawn(rt.context(), serve_n(indexer, 4), asio::detached);
    auto publish_first = co_await publisher.publish_source(indexer.self_contact(), file, first, 1s);
    EXPECT_TRUE(publish_first.has_value());
    if (!publish_first) {
      co_return;
    }
    auto publish_updated = co_await publisher.publish_source(indexer.self_contact(), file, updated, 1s);
    EXPECT_TRUE(publish_updated.has_value());
    if (!publish_updated) {
      co_return;
    }

    std::vector<Contact> peers{indexer.self_contact()};
    auto sources = co_await searcher.find_sources(peers, file, 123456789ull, 1s);
    EXPECT_TRUE(sources.has_value());
    if (!sources) {
      co_return;
    }
    EXPECT_EQ(sources->size(), 1u);
    if (sources->empty()) {
      co_return;
    }
    EXPECT_EQ((*sources)[0].answer_id, updated.answer_id);
    EXPECT_EQ(source_tcp_port((*sources)[0]), 4663);
    EXPECT_EQ(source_udp_port((*sources)[0]), 4666);
    co_return;
  });
}

TEST(KadNetwork, PublishSourceIndexesSenderIpForSearchResults) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork publisher(rt.executor(), options("00000000000000000000000000000001", 5904));
    KadNetwork indexer(rt.executor(), options("00000000000000000000000000000002", 5905));
    KadNetwork searcher(rt.executor(), options("00000000000000000000000000000003", 5906));
    const auto file = kid("00000000000000000000000000000000");
    const auto source = source_entry("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 4662, 4665, 123456789ull);

    asio::co_spawn(rt.context(), serve_n(indexer, 3), asio::detached);
    auto publish = co_await publisher.publish_source(indexer.self_contact(), file, source, 1s);
    EXPECT_TRUE(publish.has_value());
    if (!publish) {
      co_return;
    }

    std::vector<Contact> peers{indexer.self_contact()};
    auto sources = co_await searcher.find_sources(peers, file, 123456789ull, 1s);
    EXPECT_TRUE(sources.has_value());
    if (!sources || sources->empty()) {
      co_return;
    }

    auto ip = source_ip((*sources)[0]);
    EXPECT_TRUE(ip.has_value());
    if (!ip) {
      co_return;
    }
    EXPECT_EQ(ip->to_dotted(), "127.0.0.1");
    EXPECT_EQ(source_tcp_port((*sources)[0]), 4662);
    EXPECT_EQ(source_udp_port((*sources)[0]), 4665);
    co_return;
  });
}

TEST(KadNetwork, FindSourcesAggregatesAndDeduplicatesAcrossPeers) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork publisher(rt.executor(), options("00000000000000000000000000000001", 5911));
    KadNetwork first_indexer(rt.executor(), options("00000000000000000000000000000002", 5912));
    KadNetwork second_indexer(rt.executor(), options("00000000000000000000000000000003", 5913));
    KadNetwork searcher(rt.executor(), options("00000000000000000000000000000004", 5914));
    const auto file = kid("00000000000000000000000000000000");
    const auto first = source_entry("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 4662, 4665, 123456789ull);
    const auto updated = source_entry("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 4663, 4666, 123456789ull);

    asio::co_spawn(rt.context(), serve_n(first_indexer, 3), asio::detached);
    asio::co_spawn(rt.context(), serve_n(second_indexer, 3), asio::detached);
    auto publish_first = co_await publisher.publish_source(first_indexer.self_contact(), file, first, 1s);
    EXPECT_TRUE(publish_first.has_value());
    if (!publish_first) {
      co_return;
    }
    auto publish_updated = co_await publisher.publish_source(second_indexer.self_contact(), file, updated, 1s);
    EXPECT_TRUE(publish_updated.has_value());
    if (!publish_updated) {
      co_return;
    }

    std::vector<Contact> peers{first_indexer.self_contact(), second_indexer.self_contact()};
    auto sources = co_await searcher.find_sources(peers, file, 123456789ull, 1s);
    EXPECT_TRUE(sources.has_value());
    if (!sources) {
      co_return;
    }
    EXPECT_EQ(sources->size(), 1u);
    if (sources->empty()) {
      co_return;
    }
    EXPECT_EQ((*sources)[0].answer_id, updated.answer_id);
    EXPECT_EQ(source_tcp_port((*sources)[0]), 4663);
    EXPECT_EQ(source_udp_port((*sources)[0]), 4666);
    co_return;
  });
}

TEST(KadNetwork, PublishNotesThenSearchNotesFindsComment) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork publisher(rt.executor(), options("00000000000000000000000000000001", 5921));
    KadNetwork indexer(rt.executor(), options("00000000000000000000000000000002", 5922));
    KadNetwork searcher(rt.executor(), options("00000000000000000000000000000003", 5923));
    const auto file = kid("00000000000000000000000000000000");
    const auto note = note_entry("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "works", 123456789ull);

    asio::co_spawn(rt.context(), serve_n(indexer, 3), asio::detached);
    auto publish = co_await publisher.publish_notes(indexer.self_contact(), file, note, 1s);
    EXPECT_TRUE(publish.has_value());
    if (!publish) {
      co_return;
    }

    std::vector<Contact> peers{indexer.self_contact()};
    auto notes = co_await searcher.search_notes(peers, file, 123456789ull, 1s);
    EXPECT_TRUE(notes.has_value());
    if (!notes) {
      co_return;
    }
    EXPECT_EQ(notes->size(), 1u);
    if (notes->empty()) {
      co_return;
    }
    EXPECT_EQ((*notes)[0].answer_id, note.answer_id);
    EXPECT_EQ(file_size((*notes)[0]), 123456789ull);
    co_return;
  });
}

TEST(KadNetwork, FirewallUdpResultUpdatesReachabilityState) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork checker(rt.executor(), options("00000000000000000000000000000001", 5931));
    KadNetwork reporter(rt.executor(), options("00000000000000000000000000000002", 5932));

    auto sent_open = co_await reporter.send_udp_firewall_result(checker.self_contact(),
                                                                checker.self_contact().udp_port, 0);
    EXPECT_TRUE(sent_open.has_value());
    if (!sent_open) {
      co_return;
    }
    auto served_open = co_await checker.serve_once(1s);
    EXPECT_TRUE(served_open.has_value());
    if (!served_open) {
      co_return;
    }

    EXPECT_EQ(checker.udp_firewall_state(), KadFirewallState::open);
    EXPECT_TRUE(checker.last_udp_firewall_result().has_value());
    if (!checker.last_udp_firewall_result()) {
      co_return;
    }
    EXPECT_TRUE(checker.last_udp_firewall_result()->reachable);
    EXPECT_EQ(checker.last_udp_firewall_result()->incoming_port, checker.self_contact().udp_port);

    auto sent_bad_port = co_await reporter.send_udp_firewall_result(checker.self_contact(),
                                                                    checker.self_contact().udp_port + 1, 0);
    EXPECT_TRUE(sent_bad_port.has_value());
    if (!sent_bad_port) {
      co_return;
    }
    auto served_bad_port = co_await checker.serve_once(1s);
    EXPECT_TRUE(served_bad_port.has_value());
    if (!served_bad_port) {
      co_return;
    }

    EXPECT_EQ(checker.udp_firewall_state(), KadFirewallState::firewalled);
    EXPECT_TRUE(checker.last_udp_firewall_result().has_value());
    if (!checker.last_udp_firewall_result()) {
      co_return;
    }
    EXPECT_FALSE(checker.last_udp_firewall_result()->reachable);
    EXPECT_EQ(checker.last_udp_firewall_result()->sender_ip.to_dotted(), "127.0.0.1");
    co_return;
  });
}

TEST(KadNetwork, TcpFirewalledCheckReceivesExternalIpResponse) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork requester(rt.executor(), options("00000000000000000000000000000001", 5941));
    KadNetwork checker(rt.executor(), options("00000000000000000000000000000002", 5942));

    asio::co_spawn(rt.context(), serve_n(checker, 1), asio::detached);
    auto external_ip = co_await requester.check_tcp_firewall(checker.self_contact(), 1s);
    EXPECT_TRUE(external_ip.has_value());
    if (!external_ip) {
      co_return;
    }

    EXPECT_EQ(external_ip->to_dotted(), "127.0.0.1");
    EXPECT_EQ(requester.observed_external_ip()->to_dotted(), "127.0.0.1");
    co_return;
  });
}

TEST(KadNetwork, BuddyRequestEstablishesActiveBuddyOnBothPeers) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork firewalled(rt.executor(), options("00000000000000000000000000000001", 5951));
    KadNetwork open(rt.executor(), options("00000000000000000000000000000002", 5952));

    asio::co_spawn(rt.context(), serve_n(open, 1), asio::detached);
    auto buddy = co_await firewalled.request_buddy(open.self_contact(), 1s);
    EXPECT_TRUE(buddy.has_value());
    if (!buddy) {
      co_return;
    }

    EXPECT_EQ(firewalled.buddy_state(), KadBuddyState::active);
    EXPECT_EQ(open.buddy_state(), KadBuddyState::active);
    EXPECT_TRUE(firewalled.buddy().has_value());
    EXPECT_TRUE(open.buddy().has_value());
    if (!firewalled.buddy() || !open.buddy()) {
      co_return;
    }
    EXPECT_EQ(firewalled.buddy()->contact.id, open.self_contact().id);
    EXPECT_EQ(open.buddy()->contact.id, firewalled.self_contact().id);
    EXPECT_EQ(firewalled.buddy()->contact.tcp_port, open.self_contact().tcp_port);
    EXPECT_EQ(open.buddy()->contact.tcp_port, firewalled.self_contact().tcp_port);
    co_return;
  });
}

TEST(KadNetwork, BuddyCanBeMarkedInactive) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork firewalled(rt.executor(), options("00000000000000000000000000000001", 5961));
    KadNetwork open(rt.executor(), options("00000000000000000000000000000002", 5962));

    asio::co_spawn(rt.context(), serve_n(open, 1), asio::detached);
    auto buddy = co_await firewalled.request_buddy(open.self_contact(), 1s);
    EXPECT_TRUE(buddy.has_value());
    if (!buddy) {
      co_return;
    }

    firewalled.deactivate_buddy();
    EXPECT_EQ(firewalled.buddy_state(), KadBuddyState::inactive);
    EXPECT_FALSE(firewalled.buddy().has_value());
    co_return;
  });
}

TEST(KadNetwork, BuddyRecordsKadCallbackRequest) {
  net::IoRuntime rt;
  run_coro(rt, [&]() -> asio::awaitable<void> {
    KadNetwork firewalled(rt.executor(), options("00000000000000000000000000000001", 5971));
    KadNetwork open(rt.executor(), options("00000000000000000000000000000002", 5972));
    const auto file = kid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    asio::co_spawn(rt.context(), serve_n(open, 1), asio::detached);
    auto buddy = co_await firewalled.request_buddy(open.self_contact(), 1s);
    EXPECT_TRUE(buddy.has_value());
    if (!buddy || !firewalled.buddy()) {
      co_return;
    }

    auto sent_callback = co_await firewalled.send_callback(open.self_contact(),
                                                          firewalled.buddy()->buddy_id, file);
    EXPECT_TRUE(sent_callback.has_value());
    if (!sent_callback) {
      co_return;
    }
    auto served_callback = co_await open.serve_once(1s);
    EXPECT_TRUE(served_callback.has_value());
    if (!served_callback) {
      co_return;
    }

    EXPECT_TRUE(open.last_callback().has_value());
    if (!open.last_callback()) {
      co_return;
    }
    EXPECT_EQ(open.last_callback()->buddy_id, firewalled.buddy()->buddy_id);
    EXPECT_EQ(open.last_callback()->file_id, file);
    EXPECT_EQ(open.last_callback()->requester_ip.to_dotted(), "127.0.0.1");
    EXPECT_EQ(open.last_callback()->requester_tcp_port, firewalled.self_contact().tcp_port);
    co_return;
  });
}
