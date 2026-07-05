#include "ed2k/kad/network.hpp"

#include <algorithm>
#include <utility>

#include "ed2k/util/error.hpp"

namespace ed2k::kad {
namespace {
namespace asio = boost::asio;
using udp = asio::ip::udp;

IPv4 endpoint_ip(const udp::endpoint& endpoint) {
  return IPv4::from_host(endpoint.address().to_v4().to_uint());
}

udp::endpoint endpoint_from_contact(const Contact& contact) {
  return udp::endpoint(asio::ip::address_v4(contact.ip.host()), contact.udp_port);
}

tl::expected<void, std::error_code> protocol_error() {
  return tl::unexpected(make_error_code(errc::server_protocol_error));
}
} // namespace

KadNetwork::KadNetwork(asio::any_io_executor ex, KadNetworkOptions options)
    : socket_(ex, options.udp_port),
      self_(Contact{
          .id = options.id,
          .ip = options.ip,
          .udp_port = socket_.local_endpoint().port(),
          .tcp_port = options.tcp_port,
          .version = options.version,
      }),
      routing_(options.id) {}

asio::awaitable<tl::expected<Contact, std::error_code>>
KadNetwork::send_hello(udp::endpoint remote, std::chrono::milliseconds timeout) {
  auto sent = co_await socket_.send_to(remote, encode_kad2_hello_req(self_));
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }

  auto received = co_await socket_.recv_from(timeout);
  if (!received) {
    co_return tl::unexpected(received.error());
  }

  auto& packet = received->first;
  if (packet.protocol != kad_protocol || packet.opcode != opcode::kad2_hello_res) {
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));
  }

  auto contact = decode_kad2_hello(packet, endpoint_ip(received->second), received->second.port());
  if (!contact) {
    co_return tl::unexpected(contact.error());
  }

  routing_.add_or_update(*contact);
  co_return *contact;
}

asio::awaitable<tl::expected<std::vector<Contact>, std::error_code>>
KadNetwork::request_closest(const Contact& remote, KadID target, std::uint8_t count,
                            std::chrono::milliseconds timeout) {
  routing_.add_or_update(remote);

  auto sent = co_await socket_.send_to(endpoint_from_contact(remote), encode_kad2_req(target, remote.id, count));
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }

  auto received = co_await socket_.recv_from(timeout);
  if (!received) {
    co_return tl::unexpected(received.error());
  }

  auto response = decode_kad2_res(received->first);
  if (!response) {
    co_return tl::unexpected(response.error());
  }
  if (response->target != target) {
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));
  }

  for (const auto& contact : response->contacts) {
    routing_.add_or_update(contact);
  }
  co_return response->contacts;
}

asio::awaitable<tl::expected<void, std::error_code>>
KadNetwork::bootstrap(std::span<const Contact> seeds, std::chrono::milliseconds timeout) {
  std::error_code last_error = make_error_code(errc::timed_out);
  bool received_response = false;

  for (const auto& seed : seeds) {
    routing_.add_or_update(seed);

    auto hello = co_await send_hello(endpoint_from_contact(seed), timeout);
    if (!hello) {
      last_error = hello.error();
      continue;
    }
    received_response = true;

    auto closest = co_await request_closest(*hello, self_.id, KBucket::capacity, timeout);
    if (!closest) {
      last_error = closest.error();
      continue;
    }
    received_response = true;
  }

  if (!received_response) {
    co_return tl::unexpected(last_error);
  }
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<void, std::error_code>>
KadNetwork::serve_once(std::chrono::milliseconds timeout) {
  auto received = co_await socket_.recv_from(timeout);
  if (!received) {
    co_return tl::unexpected(received.error());
  }

  const auto& packet = received->first;
  const auto& sender = received->second;
  if (packet.protocol != kad_protocol) {
    co_return protocol_error();
  }

  switch (packet.opcode) {
    case opcode::kad2_hello_req: {
      auto contact = decode_kad2_hello(packet, endpoint_ip(sender), sender.port());
      if (!contact) {
        co_return tl::unexpected(contact.error());
      }
      routing_.add_or_update(*contact);

      auto response_endpoint = udp::endpoint(sender.address(), contact->udp_port);
      auto sent = co_await socket_.send_to(response_endpoint, encode_kad2_hello_res(self_));
      if (!sent) {
        co_return tl::unexpected(sent.error());
      }
      break;
    }
    case opcode::kad2_hello_res: {
      auto contact = decode_kad2_hello(packet, endpoint_ip(sender), sender.port());
      if (!contact) {
        co_return tl::unexpected(contact.error());
      }
      routing_.add_or_update(*contact);
      break;
    }
    case opcode::kad2_req: {
      auto request = decode_kad2_req(packet);
      if (!request) {
        co_return tl::unexpected(request.error());
      }
      if (request->receiver_id != self_.id) {
        co_return tl::expected<void, std::error_code>{};
      }

      auto count = std::min<std::size_t>(request->count, KBucket::capacity);
      auto contacts = routing_.closest_to(request->target, count);
      auto sent = co_await socket_.send_to(sender, encode_kad2_res(request->target, contacts));
      if (!sent) {
        co_return tl::unexpected(sent.error());
      }
      break;
    }
    case opcode::kad2_res: {
      auto response = decode_kad2_res(packet);
      if (!response) {
        co_return tl::unexpected(response.error());
      }
      for (const auto& contact : response->contacts) {
        routing_.add_or_update(contact);
      }
      break;
    }
    default:
      co_return protocol_error();
  }

  co_return tl::expected<void, std::error_code>{};
}

} // namespace ed2k::kad
