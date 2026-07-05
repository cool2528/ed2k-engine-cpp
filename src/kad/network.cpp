#include "ed2k/kad/network.hpp"

#include <algorithm>
#include <cstddef>
#include <utility>

#include "ed2k/util/error.hpp"

namespace ed2k::kad {
namespace {
namespace asio = boost::asio;
using udp = asio::ip::udp;
constexpr std::size_t k_index_response_limit = 300;
constexpr int k_search_max_rounds = 3;
constexpr std::size_t k_search_max_candidates = 50;

IPv4 endpoint_ip(const udp::endpoint& endpoint) {
  return IPv4::from_host(endpoint.address().to_v4().to_uint());
}

udp::endpoint endpoint_from_contact(const Contact& contact) {
  return udp::endpoint(asio::ip::address_v4(contact.ip.host()), contact.udp_port);
}

tl::expected<void, std::error_code> protocol_error() {
  return tl::unexpected(make_error_code(errc::server_protocol_error));
}

std::error_code protocol_error_code() {
  return make_error_code(errc::server_protocol_error);
}

void append_or_replace(std::vector<KadSearchEntry>& entries, KadSearchEntry entry) {
  const auto existing = std::find_if(entries.begin(), entries.end(), [&](const KadSearchEntry& current) {
    return current.answer_id == entry.answer_id;
  });
  if (existing != entries.end()) {
    *existing = std::move(entry);
    return;
  }
  entries.push_back(std::move(entry));
}

bool contains_id(std::span<const KadID> ids, const KadID& id) {
  return std::find(ids.begin(), ids.end(), id) != ids.end();
}

bool append_candidate(std::vector<Contact>& candidates, const Contact& contact, const KadID& self_id) {
  if (contact.id == self_id || candidates.size() >= k_search_max_candidates) {
    return false;
  }
  const auto existing = std::find_if(candidates.begin(), candidates.end(), [&](const Contact& current) {
    return current.id == contact.id;
  });
  if (existing != candidates.end()) {
    return false;
  }
  candidates.push_back(contact);
  return true;
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

asio::awaitable<tl::expected<KadPublishResponse, std::error_code>>
KadNetwork::publish_keyword(const Contact& remote, KadID key_id, std::span<const KadSearchEntry> entries,
                            std::chrono::milliseconds timeout) {
  routing_.add_or_update(remote);

  auto sent = co_await socket_.send_to(endpoint_from_contact(remote), encode_kad2_publish_key_req(key_id, entries));
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }

  auto received = co_await socket_.recv_from(timeout);
  if (!received) {
    co_return tl::unexpected(received.error());
  }

  auto response = decode_kad2_publish_res(received->first);
  if (!response) {
    co_return tl::unexpected(response.error());
  }
  if (response->target != key_id) {
    co_return tl::unexpected(protocol_error_code());
  }

  co_return *response;
}

asio::awaitable<tl::expected<KadPublishResponse, std::error_code>>
KadNetwork::publish_source(const Contact& remote, KadID file_id, const KadSearchEntry& source,
                           std::chrono::milliseconds timeout) {
  routing_.add_or_update(remote);

  auto sent = co_await socket_.send_to(endpoint_from_contact(remote), encode_kad2_publish_source_req(file_id, source));
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }

  auto received = co_await socket_.recv_from(timeout);
  if (!received) {
    co_return tl::unexpected(received.error());
  }

  auto response = decode_kad2_publish_res(received->first);
  if (!response) {
    co_return tl::unexpected(response.error());
  }
  if (response->target != file_id) {
    co_return tl::unexpected(protocol_error_code());
  }

  co_return *response;
}

asio::awaitable<tl::expected<KadPublishResponse, std::error_code>>
KadNetwork::publish_notes(const Contact& remote, KadID file_id, const KadSearchEntry& note,
                          std::chrono::milliseconds timeout) {
  routing_.add_or_update(remote);

  auto sent = co_await socket_.send_to(endpoint_from_contact(remote), encode_kad2_publish_notes_req(file_id, note));
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }

  auto received = co_await socket_.recv_from(timeout);
  if (!received) {
    co_return tl::unexpected(received.error());
  }

  auto response = decode_kad2_publish_res(received->first);
  if (!response) {
    co_return tl::unexpected(response.error());
  }
  if (response->target != file_id) {
    co_return tl::unexpected(protocol_error_code());
  }

  co_return *response;
}

asio::awaitable<tl::expected<std::vector<KadSearchEntry>, std::error_code>>
KadNetwork::search_keyword(std::span<const Contact> peers, KadID key_id, std::chrono::milliseconds timeout) {
  std::vector<KadSearchEntry> entries;
  std::vector<Contact> candidates(peers.begin(), peers.end());
  std::vector<KadID> searched;
  std::vector<KadID> expanded;
  std::error_code last_error = make_error_code(errc::timed_out);
  bool received_response = false;

  for (int round = 0; round < k_search_max_rounds; ++round) {
    bool progressed = false;
    const auto round_count = candidates.size();

    for (std::size_t i = 0; i < round_count; ++i) {
      const auto peer = candidates[i];
      if (contains_id(searched, peer.id)) {
        continue;
      }
      searched.push_back(peer.id);
      routing_.add_or_update(peer);

      auto sent = co_await socket_.send_to(endpoint_from_contact(peer), encode_kad2_search_key_req(key_id, 0));
      if (!sent) {
        last_error = sent.error();
      } else {
        auto received = co_await socket_.recv_from(timeout);
        if (!received) {
          last_error = received.error();
        } else {
          auto response = decode_kad2_search_res(received->first);
          if (!response) {
            last_error = response.error();
          } else if (response->target != key_id) {
            last_error = protocol_error_code();
          } else {
            received_response = true;
            if (!response->entries.empty()) {
              progressed = true;
              for (auto& entry : response->entries) {
                append_or_replace(entries, std::move(entry));
              }
              continue;
            }
          }
        }
      }

      if (contains_id(expanded, peer.id)) {
        continue;
      }
      expanded.push_back(peer.id);
      auto closest = co_await request_closest(peer, key_id, KBucket::capacity, timeout);
      if (!closest) {
        last_error = closest.error();
        continue;
      }
      for (const auto& contact : *closest) {
        progressed = append_candidate(candidates, contact, self_.id) || progressed;
      }
    }

    if (!progressed) {
      break;
    }
  }

  if (!received_response) {
    co_return tl::unexpected(last_error);
  }
  co_return entries;
}

asio::awaitable<tl::expected<std::vector<KadSearchEntry>, std::error_code>>
KadNetwork::find_sources(std::span<const Contact> peers, KadID file_id, std::uint64_t file_size,
                         std::chrono::milliseconds timeout) {
  std::vector<KadSearchEntry> entries;
  std::vector<Contact> candidates(peers.begin(), peers.end());
  std::vector<KadID> searched;
  std::vector<KadID> expanded;
  std::error_code last_error = make_error_code(errc::timed_out);
  bool received_response = false;

  for (int round = 0; round < k_search_max_rounds; ++round) {
    bool progressed = false;
    const auto round_count = candidates.size();

    for (std::size_t i = 0; i < round_count; ++i) {
      const auto peer = candidates[i];
      if (contains_id(searched, peer.id)) {
        continue;
      }
      searched.push_back(peer.id);
      routing_.add_or_update(peer);

      auto sent = co_await socket_.send_to(endpoint_from_contact(peer),
                                          encode_kad2_search_source_req(file_id, 0, file_size));
      if (!sent) {
        last_error = sent.error();
      } else {
        auto received = co_await socket_.recv_from(timeout);
        if (!received) {
          last_error = received.error();
        } else {
          auto response = decode_kad2_search_res(received->first);
          if (!response) {
            last_error = response.error();
          } else if (response->target != file_id) {
            last_error = protocol_error_code();
          } else {
            received_response = true;
            if (!response->entries.empty()) {
              progressed = true;
              for (auto& entry : response->entries) {
                append_or_replace(entries, std::move(entry));
              }
              continue;
            }
          }
        }
      }

      if (contains_id(expanded, peer.id)) {
        continue;
      }
      expanded.push_back(peer.id);
      auto closest = co_await request_closest(peer, file_id, KBucket::capacity, timeout);
      if (!closest) {
        last_error = closest.error();
        continue;
      }
      for (const auto& contact : *closest) {
        progressed = append_candidate(candidates, contact, self_.id) || progressed;
      }
    }

    if (!progressed) {
      break;
    }
  }

  if (!received_response) {
    co_return tl::unexpected(last_error);
  }
  co_return entries;
}

asio::awaitable<tl::expected<std::vector<KadSearchEntry>, std::error_code>>
KadNetwork::search_notes(std::span<const Contact> peers, KadID file_id, std::uint64_t file_size,
                         std::chrono::milliseconds timeout) {
  std::vector<KadSearchEntry> entries;
  std::vector<Contact> candidates(peers.begin(), peers.end());
  std::vector<KadID> searched;
  std::vector<KadID> expanded;
  std::error_code last_error = make_error_code(errc::timed_out);
  bool received_response = false;

  for (int round = 0; round < k_search_max_rounds; ++round) {
    bool progressed = false;
    const auto round_count = candidates.size();

    for (std::size_t i = 0; i < round_count; ++i) {
      const auto peer = candidates[i];
      if (contains_id(searched, peer.id)) {
        continue;
      }
      searched.push_back(peer.id);
      routing_.add_or_update(peer);

      auto sent = co_await socket_.send_to(endpoint_from_contact(peer),
                                          encode_kad2_search_notes_req(file_id, file_size));
      if (!sent) {
        last_error = sent.error();
      } else {
        auto received = co_await socket_.recv_from(timeout);
        if (!received) {
          last_error = received.error();
        } else {
          auto response = decode_kad2_search_res(received->first);
          if (!response) {
            last_error = response.error();
          } else if (response->target != file_id) {
            last_error = protocol_error_code();
          } else {
            received_response = true;
            if (!response->entries.empty()) {
              progressed = true;
              for (auto& entry : response->entries) {
                append_or_replace(entries, std::move(entry));
              }
              continue;
            }
          }
        }
      }

      if (contains_id(expanded, peer.id)) {
        continue;
      }
      expanded.push_back(peer.id);
      auto closest = co_await request_closest(peer, file_id, KBucket::capacity, timeout);
      if (!closest) {
        last_error = closest.error();
        continue;
      }
      for (const auto& contact : *closest) {
        progressed = append_candidate(candidates, contact, self_.id) || progressed;
      }
    }

    if (!progressed) {
      break;
    }
  }

  if (!received_response) {
    co_return tl::unexpected(last_error);
  }
  co_return entries;
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
    case opcode::kad2_search_key_req: {
      auto request = decode_kad2_search_key_req(packet);
      if (!request) {
        co_return tl::unexpected(request.error());
      }
      auto entries = indexed_.search_keyword(request->target, k_index_response_limit);
      auto sent = co_await socket_.send_to(sender, encode_kad2_search_res(self_.id, request->target, entries));
      if (!sent) {
        co_return tl::unexpected(sent.error());
      }
      break;
    }
    case opcode::kad2_search_source_req: {
      auto request = decode_kad2_search_source_req(packet);
      if (!request) {
        co_return tl::unexpected(request.error());
      }
      auto entries = indexed_.search_sources(request->target, request->file_size, k_index_response_limit);
      auto sent = co_await socket_.send_to(sender, encode_kad2_search_res(self_.id, request->target, entries));
      if (!sent) {
        co_return tl::unexpected(sent.error());
      }
      break;
    }
    case opcode::kad2_search_notes_req: {
      auto request = decode_kad2_search_notes_req(packet);
      if (!request) {
        co_return tl::unexpected(request.error());
      }
      auto entries = indexed_.search_notes(request->target, request->file_size, k_index_response_limit);
      auto sent = co_await socket_.send_to(sender, encode_kad2_search_res(self_.id, request->target, entries));
      if (!sent) {
        co_return tl::unexpected(sent.error());
      }
      break;
    }
    case opcode::kad2_search_res: {
      auto response = decode_kad2_search_res(packet);
      if (!response) {
        co_return tl::unexpected(response.error());
      }
      break;
    }
    case opcode::kad2_publish_key_req: {
      auto request = decode_kad2_publish_key_req(packet);
      if (!request) {
        co_return tl::unexpected(request.error());
      }
      for (auto& entry : request->entries) {
        indexed_.add_keyword(request->key_id, std::move(entry));
      }
      auto sent = co_await socket_.send_to(sender, encode_kad2_publish_res(request->key_id, 0));
      if (!sent) {
        co_return tl::unexpected(sent.error());
      }
      break;
    }
    case opcode::kad2_publish_source_req: {
      auto request = decode_kad2_publish_source_req(packet);
      if (!request) {
        co_return tl::unexpected(request.error());
      }
      indexed_.add_source(request->file_id, std::move(request->source));
      auto sent = co_await socket_.send_to(sender, encode_kad2_publish_res(request->file_id, 0));
      if (!sent) {
        co_return tl::unexpected(sent.error());
      }
      break;
    }
    case opcode::kad2_publish_notes_req: {
      auto request = decode_kad2_publish_notes_req(packet);
      if (!request) {
        co_return tl::unexpected(request.error());
      }
      indexed_.add_note(request->file_id, std::move(request->note));
      auto sent = co_await socket_.send_to(sender, encode_kad2_publish_res(request->file_id, 0));
      if (!sent) {
        co_return tl::unexpected(sent.error());
      }
      break;
    }
    case opcode::kad2_publish_res: {
      auto response = decode_kad2_publish_res(packet);
      if (!response) {
        co_return tl::unexpected(response.error());
      }
      break;
    }
    case opcode::kad2_publish_res_ack:
      break;
    default:
      co_return protocol_error();
  }

  co_return tl::expected<void, std::error_code>{};
}

} // namespace ed2k::kad
