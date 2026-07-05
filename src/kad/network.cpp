#include "ed2k/kad/network.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>

#include "ed2k/kad/udp_crypto.hpp"
#include "ed2k/net/udp_framing.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::kad {
namespace {
namespace asio = boost::asio;
using udp = asio::ip::udp;
constexpr std::size_t k_index_response_limit = 300;
constexpr std::size_t k_search_max_candidates = 300;
constexpr std::uint32_t k_search_tolerance = 16777216;
constexpr std::chrono::milliseconds k_search_step_timeout{500};

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

void sort_candidates_by_target(std::vector<Contact>& candidates, const KadID& target) {
  std::sort(candidates.begin(), candidates.end(), [&](const Contact& lhs, const Contact& rhs) {
    return closer_to_target(lhs.id, rhs.id, target);
  });
}

bool append_candidate(std::vector<Contact>& candidates, const Contact& contact, const KadID& self_id,
                      const KadID& target) {
  if (contact.id == self_id) {
    return false;
  }
  const auto existing = std::find_if(candidates.begin(), candidates.end(), [&](const Contact& current) {
    return current.id == contact.id;
  });
  if (existing != candidates.end()) {
    return false;
  }
  candidates.push_back(contact);
  sort_candidates_by_target(candidates, target);
  if (candidates.size() <= k_search_max_candidates) {
    return true;
  }
  const bool retained = candidates.back().id != contact.id;
  candidates.pop_back();
  return retained;
}

std::uint32_t distance_msw(const KadID& lhs, const KadID& rhs) noexcept {
  const auto distance = xor_distance(lhs, rhs).bytes();
  return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(distance[0])) << 24) |
         (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(distance[1])) << 16) |
         (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(distance[2])) << 8) |
         static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(distance[3]));
}

bool is_zero_id(const KadID& id) noexcept {
  return std::all_of(id.bytes().begin(), id.bytes().end(), [](std::byte value) {
    return value == std::byte{0};
  });
}

bool is_within_search_tolerance(const KadID& peer_id, const KadID& target) noexcept {
  return distance_msw(peer_id, target) <= k_search_tolerance;
}

std::vector<Contact>::const_iterator next_unsearched_candidate(const std::vector<Contact>& candidates,
                                                               std::span<const KadID> searched) {
  return std::find_if(candidates.begin(), candidates.end(), [&](const Contact& candidate) {
    return !contains_id(searched, candidate.id);
  });
}

bool has_tag(const KadSearchEntry& entry, std::uint8_t name_id) noexcept {
  return std::any_of(entry.tags.begin(), entry.tags.end(), [&](const codec::Tag& tag_value) {
    if (tag_value.name_id == name_id) {
      return true;
    }
    return tag_value.name_str.size() == 1 &&
           static_cast<std::uint8_t>(static_cast<unsigned char>(tag_value.name_str[0])) == name_id;
  });
}

bool kad_trace_enabled() noexcept {
  static const bool enabled = [] {
    const char* value = std::getenv("ED2K_KAD_TRACE");
    return value != nullptr && value[0] != '\0' && value[0] != '0';
  }();
  return enabled;
}

void trace_packet(const char* direction, const udp::endpoint& endpoint, const net::Packet& packet,
                  const char* detail) {
  if (!kad_trace_enabled()) {
    return;
  }
  std::fprintf(stderr, "[kad] %s %s:%u proto=0x%02x op=0x%02x payload=%zu %s\n",
               direction,
               endpoint.address().to_string().c_str(),
               endpoint.port(),
               packet.protocol,
               packet.opcode,
               packet.payload.size(),
               detail);
}

void trace_datagram_error(const udp::endpoint& endpoint, std::size_t size, const char* detail,
                          const std::error_code& error) {
  if (!kad_trace_enabled()) {
    return;
  }
  std::fprintf(stderr, "[kad] rx %s:%u datagram=%zu %s error=%s\n",
               endpoint.address().to_string().c_str(),
               endpoint.port(),
               size,
               detail,
               error.message().c_str());
}

void trace_search_candidate(const char* kind, const Contact& peer, const KadID& target) {
  if (!kad_trace_enabled()) {
    return;
  }
  const auto msw = distance_msw(peer.id, target);
  std::fprintf(stderr, "[kad] search-%s peer=%s:%u distance_msw=%u within_tolerance=%u\n",
               kind,
               peer.ip.to_dotted().c_str(),
               peer.udp_port,
               msw,
               msw <= k_search_tolerance ? 1u : 0u);
}

void trace_search_response(const char* kind, const udp::endpoint& endpoint, const char* detail,
                           const std::error_code& error = {}) {
  if (!kad_trace_enabled()) {
    return;
  }
  std::fprintf(stderr, "[kad] search-%s-response %s:%u %s%s%s\n",
               kind,
               endpoint.address().to_string().c_str(),
               endpoint.port(),
               detail,
               error ? " error=" : "",
               error ? error.message().c_str() : "");
}

std::chrono::milliseconds remaining_until(std::chrono::steady_clock::time_point deadline) {
  auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
      deadline - std::chrono::steady_clock::now());
  if (remaining.count() <= 0) {
    remaining = std::chrono::milliseconds(1);
  }
  return remaining;
}

std::chrono::milliseconds bounded_remaining_until(std::chrono::steady_clock::time_point deadline,
                                                  std::chrono::milliseconds cap) {
  auto remaining = remaining_until(deadline);
  return remaining < cap ? remaining : cap;
}

codec::Tag int_tag(std::uint8_t name_id, std::uint64_t value) {
  codec::Tag tag_value;
  tag_value.name_str = std::string(1, static_cast<char>(name_id));
  tag_value.value = value;
  return tag_value;
}

KadID fallback_user_hash(const KadNetworkOptions& options) noexcept {
  if (!is_zero_id(options.user_hash)) {
    return options.user_hash;
  }
  return options.id;
}

KadID bitwise_not_id(const KadID& id) noexcept {
  std::array<std::byte, KadID::size> bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = std::byte{static_cast<unsigned char>(~std::to_integer<unsigned char>(id.bytes()[i]))};
  }
  return KadID::from_bytes(bytes);
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
      user_hash_(fallback_user_hash(options)),
      kad_udp_key_(options.kad_udp_key == 0 ? 0x4b414432u : options.kad_udp_key),
      routing_(options.id) {}

asio::awaitable<tl::expected<void, std::error_code>>
KadNetwork::send_kad_packet(const Contact& remote, const net::Packet& packet) {
  const auto endpoint = endpoint_from_contact(remote);
  if (remote.version >= 6) {
    trace_packet("tx", endpoint, packet, "target-id-obfuscated");
    auto encoded = encode_kad_obfuscated_datagram(net::encode_udp_packet(packet),
                                                  KadUdpEncryptOptions{
                                                      .target_id = remote.id,
                                                      .sender_verify_key = kad_udp_verify_key(kad_udp_key_, remote.ip),
                                                  });
    if (!encoded) {
      co_return tl::unexpected(encoded.error());
    }
    auto sent = co_await socket_.send_datagram(endpoint, *encoded);
    if (!sent) {
      co_return tl::unexpected(sent.error());
    }
    co_return tl::expected<void, std::error_code>{};
  }

  trace_packet("tx", endpoint, packet, "clear");
  auto sent = co_await socket_.send_to(endpoint, packet);
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<void, std::error_code>>
KadNetwork::send_kad_packet(udp::endpoint remote, const net::Packet& packet,
                            std::uint32_t receiver_verify_key) {
  if (receiver_verify_key != 0) {
    trace_packet("tx", remote, packet, "receiver-key-obfuscated");
    const auto remote_ip = endpoint_ip(remote);
    auto encoded = encode_kad_obfuscated_datagram(net::encode_udp_packet(packet),
                                                  KadUdpEncryptOptions{
                                                      .receiver_verify_key = receiver_verify_key,
                                                      .sender_verify_key = kad_udp_verify_key(kad_udp_key_, remote_ip),
                                                  });
    if (!encoded) {
      co_return tl::unexpected(encoded.error());
    }
    auto sent = co_await socket_.send_datagram(remote, *encoded);
    if (!sent) {
      co_return tl::unexpected(sent.error());
    }
    co_return tl::expected<void, std::error_code>{};
  }

  trace_packet("tx", remote, packet, "clear");
  auto sent = co_await socket_.send_to(remote, packet);
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<KadNetwork::ReceivedPacket, std::error_code>>
KadNetwork::recv_kad_packet(std::chrono::milliseconds timeout) {
  auto received = co_await socket_.recv_datagram(timeout);
  if (!received) {
    co_return tl::unexpected(received.error());
  }

  const auto sender_ip = endpoint_ip(received->second);
  auto decoded = decode_kad_obfuscated_datagram(received->first, self_.id,
                                                kad_udp_verify_key(kad_udp_key_, sender_ip));
  if (!decoded) {
    trace_datagram_error(received->second, received->first.size(), "decode", decoded.error());
    co_return tl::unexpected(decoded.error());
  }

  auto packet = net::parse_udp_datagram(decoded->datagram);
  if (!packet) {
    trace_datagram_error(received->second, decoded->datagram.size(), "parse", packet.error());
    co_return tl::unexpected(packet.error());
  }

  trace_packet("rx", received->second, *packet,
               decoded->encrypted
                   ? (decoded->valid_receiver_key ? "encrypted receiver-key" : "encrypted target-id")
                   : "clear");

  co_return ReceivedPacket{
      .packet = std::move(*packet),
      .sender = received->second,
      .sender_verify_key = decoded->sender_verify_key,
      .encrypted = decoded->encrypted,
      .valid_receiver_key = decoded->valid_receiver_key,
  };
}

void KadNetwork::deactivate_buddy() noexcept {
  buddy_.reset();
  buddy_state_ = KadBuddyState::inactive;
}

asio::awaitable<tl::expected<Contact, std::error_code>>
KadNetwork::send_hello(udp::endpoint remote, std::chrono::milliseconds timeout) {
  auto sent = co_await send_kad_packet(remote, encode_kad2_hello_req(self_), 0);
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }

  auto received = co_await recv_kad_packet(timeout);
  if (!received) {
    co_return tl::unexpected(received.error());
  }

  auto& packet = received->packet;
  if (packet.protocol != kad_protocol || packet.opcode != opcode::kad2_hello_res) {
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));
  }

  auto contact = decode_kad2_hello(packet, endpoint_ip(received->sender), received->sender.port());
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

  auto sent = co_await send_kad_packet(remote, encode_kad2_req(target, remote.id, count));
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }

  std::error_code last_error = make_error_code(errc::timed_out);
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    auto received = co_await recv_kad_packet(remaining_until(deadline));
    if (!received) {
      last_error = received.error();
      if (last_error == make_error_code(errc::timed_out)) {
        break;
      }
      continue;
    }

    auto response = decode_kad2_res(received->packet);
    if (!response) {
      last_error = response.error();
      continue;
    }
    if (response->target != target) {
      last_error = protocol_error_code();
      continue;
    }

    for (const auto& contact : response->contacts) {
      routing_.add_or_update(contact);
    }
    co_return response->contacts;
  }

  co_return tl::unexpected(last_error);
}

asio::awaitable<tl::expected<void, std::error_code>>
KadNetwork::bootstrap(std::span<const Contact> seeds, std::chrono::milliseconds timeout) {
  std::error_code last_error = make_error_code(errc::timed_out);
  bool sent_any = false;

  for (const auto& seed : seeds) {
    routing_.add_or_update(seed);

    auto sent_bootstrap = co_await send_kad_packet(seed, encode_kad2_bootstrap_req());
    if (!sent_bootstrap) {
      last_error = sent_bootstrap.error();
    } else {
      sent_any = true;
    }
  }

  if (sent_any) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
          deadline - std::chrono::steady_clock::now());
      if (remaining.count() <= 0) {
        remaining = std::chrono::milliseconds(1);
      }

      auto received_bootstrap = co_await recv_kad_packet(remaining);
      if (!received_bootstrap) {
        last_error = received_bootstrap.error();
        if (last_error == make_error_code(errc::timed_out)) {
          break;
        }
        continue;
      }

      auto response = decode_kad2_bootstrap_res(received_bootstrap->packet,
                                                endpoint_ip(received_bootstrap->sender),
                                                received_bootstrap->sender.port());
      if (!response) {
        last_error = response.error();
        continue;
      }

      routing_.add_or_update(response->sender);
      for (const auto& contact : response->contacts) {
        routing_.add_or_update(contact);
      }
      co_return tl::expected<void, std::error_code>{};
    }
  }

  sent_any = false;
  for (const auto& seed : seeds) {
    auto sent_hello = co_await send_kad_packet(endpoint_from_contact(seed), encode_kad2_hello_req(self_), 0);
    if (!sent_hello) {
      last_error = sent_hello.error();
    } else {
      sent_any = true;
    }
  }

  if (!sent_any) {
    co_return tl::unexpected(last_error);
  }

  const auto hello_deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < hello_deadline) {
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        hello_deadline - std::chrono::steady_clock::now());
    if (remaining.count() <= 0) {
      remaining = std::chrono::milliseconds(1);
    }

    auto received_hello = co_await recv_kad_packet(remaining);
    if (!received_hello) {
      last_error = received_hello.error();
      if (last_error == make_error_code(errc::timed_out)) {
        break;
      }
      continue;
    }

    auto& packet = received_hello->packet;
    if (packet.protocol != kad_protocol || packet.opcode != opcode::kad2_hello_res) {
      last_error = protocol_error_code();
      continue;
    }

    auto hello = decode_kad2_hello(packet, endpoint_ip(received_hello->sender), received_hello->sender.port());
    if (!hello) {
      last_error = hello.error();
      continue;
    }
    routing_.add_or_update(*hello);

    auto closest = co_await request_closest(*hello, self_.id, KBucket::capacity, timeout);
    if (!closest) {
      last_error = closest.error();
      co_return tl::expected<void, std::error_code>{};
    }
    co_return tl::expected<void, std::error_code>{};
  }

  co_return tl::unexpected(last_error);
}

asio::awaitable<tl::expected<KadPublishResponse, std::error_code>>
KadNetwork::publish_keyword(const Contact& remote, KadID key_id, std::span<const KadSearchEntry> entries,
                            std::chrono::milliseconds timeout) {
  routing_.add_or_update(remote);

  auto sent = co_await send_kad_packet(remote, encode_kad2_publish_key_req(key_id, entries));
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }

  std::error_code last_error = make_error_code(errc::timed_out);
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    auto received = co_await recv_kad_packet(remaining_until(deadline));
    if (!received) {
      last_error = received.error();
      if (last_error == make_error_code(errc::timed_out)) {
        break;
      }
      continue;
    }

    auto response = decode_kad2_publish_res(received->packet);
    if (!response) {
      last_error = response.error();
      continue;
    }
    if (response->target != key_id) {
      last_error = protocol_error_code();
      continue;
    }

    co_return *response;
  }

  co_return tl::unexpected(last_error);
}

asio::awaitable<tl::expected<KadPublishResponse, std::error_code>>
KadNetwork::publish_source(const Contact& remote, KadID file_id, const KadSearchEntry& source,
                           std::chrono::milliseconds timeout) {
  routing_.add_or_update(remote);

  auto sent = co_await send_kad_packet(remote, encode_kad2_publish_source_req(file_id, source));
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }

  std::error_code last_error = make_error_code(errc::timed_out);
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    auto received = co_await recv_kad_packet(remaining_until(deadline));
    if (!received) {
      last_error = received.error();
      if (last_error == make_error_code(errc::timed_out)) {
        break;
      }
      continue;
    }

    auto response = decode_kad2_publish_res(received->packet);
    if (!response) {
      last_error = response.error();
      continue;
    }
    if (response->target != file_id) {
      last_error = protocol_error_code();
      continue;
    }

    co_return *response;
  }

  co_return tl::unexpected(last_error);
}

asio::awaitable<tl::expected<KadPublishResponse, std::error_code>>
KadNetwork::publish_notes(const Contact& remote, KadID file_id, const KadSearchEntry& note,
                          std::chrono::milliseconds timeout) {
  routing_.add_or_update(remote);

  auto sent = co_await send_kad_packet(remote, encode_kad2_publish_notes_req(file_id, note));
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }

  std::error_code last_error = make_error_code(errc::timed_out);
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    auto received = co_await recv_kad_packet(remaining_until(deadline));
    if (!received) {
      last_error = received.error();
      if (last_error == make_error_code(errc::timed_out)) {
        break;
      }
      continue;
    }

    auto response = decode_kad2_publish_res(received->packet);
    if (!response) {
      last_error = response.error();
      continue;
    }
    if (response->target != file_id) {
      last_error = protocol_error_code();
      continue;
    }

    co_return *response;
  }

  co_return tl::unexpected(last_error);
}

asio::awaitable<tl::expected<std::vector<KadSearchEntry>, std::error_code>>
KadNetwork::search_keyword(std::span<const Contact> peers, KadID key_id, std::chrono::milliseconds timeout) {
  std::vector<KadSearchEntry> entries;
  std::vector<Contact> candidates(peers.begin(), peers.end());
  std::vector<KadID> searched;
  std::error_code last_error = make_error_code(errc::timed_out);
  bool received_response = false;
  const auto search_deadline = std::chrono::steady_clock::now() + timeout;
  sort_candidates_by_target(candidates, key_id);

  while (std::chrono::steady_clock::now() < search_deadline &&
         searched.size() < k_search_max_candidates) {
    const auto next = next_unsearched_candidate(candidates, searched);
    if (next == candidates.end()) {
      break;
    }

    const auto peer = *next;
    searched.push_back(peer.id);
    routing_.add_or_update(peer);

    trace_search_candidate("lookup-keyword", peer, key_id);
    auto closest = co_await request_closest(peer, key_id, KBucket::capacity,
                                            bounded_remaining_until(search_deadline,
                                                                    k_search_step_timeout));
    if (!closest) {
      last_error = closest.error();
    } else {
      for (const auto& contact : *closest) {
        append_candidate(candidates, contact, self_.id, key_id);
      }
    }

    if (std::chrono::steady_clock::now() >= search_deadline ||
        !is_within_search_tolerance(peer.id, key_id)) {
      continue;
    }

    trace_search_candidate("keyword", peer, key_id);
    auto sent = co_await send_kad_packet(peer, encode_kad2_search_key_req(key_id, 0));
    if (!sent) {
      last_error = sent.error();
      continue;
    }

    while (std::chrono::steady_clock::now() < search_deadline) {
      auto received = co_await recv_kad_packet(
          bounded_remaining_until(search_deadline, k_search_step_timeout));
      if (!received) {
        last_error = received.error();
        if (last_error == make_error_code(errc::timed_out)) {
          break;
        }
        continue;
      }

      auto response = decode_kad2_search_res(received->packet);
      if (!response) {
        last_error = response.error();
        if (received->packet.protocol == kad_protocol && received->packet.opcode == opcode::kad2_search_res) {
          trace_search_response("keyword", received->sender, "decode-failed", response.error());
        }
        continue;
      }
      if (response->target != key_id) {
        last_error = protocol_error_code();
        trace_search_response("keyword", received->sender, "target-mismatch");
        continue;
      }

      received_response = true;
      if (response->entries.empty()) {
        trace_search_response("keyword", received->sender, "empty");
      }
      if (!response->entries.empty()) {
        trace_search_response("keyword", received->sender, "accepted");
        for (auto& entry : response->entries) {
          append_or_replace(entries, std::move(entry));
        }
      }
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
  std::error_code last_error = make_error_code(errc::timed_out);
  bool received_response = false;
  const auto search_deadline = std::chrono::steady_clock::now() + timeout;
  sort_candidates_by_target(candidates, file_id);

  while (std::chrono::steady_clock::now() < search_deadline &&
         searched.size() < k_search_max_candidates) {
    const auto next = next_unsearched_candidate(candidates, searched);
    if (next == candidates.end()) {
      break;
    }

    const auto peer = *next;
    searched.push_back(peer.id);
    routing_.add_or_update(peer);

    trace_search_candidate("lookup-source", peer, file_id);
    auto closest = co_await request_closest(peer, file_id, KBucket::capacity,
                                            bounded_remaining_until(search_deadline,
                                                                    k_search_step_timeout));
    if (!closest) {
      last_error = closest.error();
    } else {
      for (const auto& contact : *closest) {
        append_candidate(candidates, contact, self_.id, file_id);
      }
    }

    if (std::chrono::steady_clock::now() >= search_deadline ||
        !is_within_search_tolerance(peer.id, file_id)) {
      continue;
    }

    trace_search_candidate("source", peer, file_id);
    auto sent = co_await send_kad_packet(peer, encode_kad2_search_source_req(file_id, 0, file_size));
    if (!sent) {
      last_error = sent.error();
      continue;
    }

    while (std::chrono::steady_clock::now() < search_deadline) {
      auto received = co_await recv_kad_packet(
          bounded_remaining_until(search_deadline, k_search_step_timeout));
      if (!received) {
        last_error = received.error();
        if (last_error == make_error_code(errc::timed_out)) {
          break;
        }
        continue;
      }

      auto response = decode_kad2_search_res(received->packet);
      if (!response) {
        last_error = response.error();
        continue;
      }
      if (response->target != file_id) {
        last_error = protocol_error_code();
        continue;
      }

      received_response = true;
      if (!response->entries.empty()) {
        for (auto& entry : response->entries) {
          append_or_replace(entries, std::move(entry));
        }
      }
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
  std::error_code last_error = make_error_code(errc::timed_out);
  bool received_response = false;
  const auto search_deadline = std::chrono::steady_clock::now() + timeout;
  sort_candidates_by_target(candidates, file_id);

  while (std::chrono::steady_clock::now() < search_deadline &&
         searched.size() < k_search_max_candidates) {
    const auto next = next_unsearched_candidate(candidates, searched);
    if (next == candidates.end()) {
      break;
    }

    const auto peer = *next;
    searched.push_back(peer.id);
    routing_.add_or_update(peer);

    trace_search_candidate("lookup-notes", peer, file_id);
    auto closest = co_await request_closest(peer, file_id, KBucket::capacity,
                                            bounded_remaining_until(search_deadline,
                                                                    k_search_step_timeout));
    if (!closest) {
      last_error = closest.error();
    } else {
      for (const auto& contact : *closest) {
        append_candidate(candidates, contact, self_.id, file_id);
      }
    }

    if (std::chrono::steady_clock::now() >= search_deadline ||
        !is_within_search_tolerance(peer.id, file_id)) {
      continue;
    }

    trace_search_candidate("notes", peer, file_id);
    auto sent = co_await send_kad_packet(peer, encode_kad2_search_notes_req(file_id, file_size));
    if (!sent) {
      last_error = sent.error();
      continue;
    }

    while (std::chrono::steady_clock::now() < search_deadline) {
      auto received = co_await recv_kad_packet(
          bounded_remaining_until(search_deadline, k_search_step_timeout));
      if (!received) {
        last_error = received.error();
        if (last_error == make_error_code(errc::timed_out)) {
          break;
        }
        continue;
      }

      auto response = decode_kad2_search_res(received->packet);
      if (!response) {
        last_error = response.error();
        continue;
      }
      if (response->target != file_id) {
        last_error = protocol_error_code();
        continue;
      }

      received_response = true;
      if (!response->entries.empty()) {
        for (auto& entry : response->entries) {
          append_or_replace(entries, std::move(entry));
        }
      }
      break;
    }
  }

  if (!received_response) {
    co_return tl::unexpected(last_error);
  }
  co_return entries;
}

asio::awaitable<tl::expected<IPv4, std::error_code>>
KadNetwork::check_tcp_firewall(const Contact& remote, std::chrono::milliseconds timeout) {
  routing_.add_or_update(remote);

  auto request_packet = remote.version > 6 ? encode_kademlia_firewalled2_req(self_.tcp_port, user_hash_, 0)
                                           : encode_kademlia_firewalled_req(self_.tcp_port);
  auto sent = co_await send_kad_packet(remote, request_packet);
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }

  auto received = co_await recv_kad_packet(timeout);
  if (!received) {
    co_return tl::unexpected(received.error());
  }

  auto response = decode_kademlia_firewalled_res(received->packet);
  if (!response) {
    co_return tl::unexpected(response.error());
  }

  observed_external_ip_ = response->ip;
  co_return response->ip;
}

asio::awaitable<tl::expected<void, std::error_code>>
KadNetwork::send_udp_firewall_result(const Contact& remote, std::uint16_t incoming_port,
                                     std::uint8_t error_code) {
  auto sent = co_await send_kad_packet(remote, encode_kad2_firewall_udp(error_code, incoming_port));
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<KadBuddyInfo, std::error_code>>
KadNetwork::request_buddy(const Contact& remote, std::chrono::milliseconds timeout) {
  routing_.add_or_update(remote);
  buddy_state_ = KadBuddyState::connecting;

  const auto buddy_id = bitwise_not_id(self_.id);
  auto sent = co_await send_kad_packet(remote, encode_kademlia_find_buddy_req(buddy_id, user_hash_, self_.tcp_port));
  if (!sent) {
    deactivate_buddy();
    co_return tl::unexpected(sent.error());
  }

  auto received = co_await recv_kad_packet(timeout);
  if (!received) {
    deactivate_buddy();
    co_return tl::unexpected(received.error());
  }

  auto response = decode_kademlia_find_buddy_res(received->packet);
  if (!response) {
    deactivate_buddy();
    co_return tl::unexpected(response.error());
  }
  if (bitwise_not_id(response->buddy_id) != self_.id) {
    deactivate_buddy();
    co_return tl::unexpected(protocol_error_code());
  }

  Contact buddy_contact = remote;
  buddy_contact.tcp_port = response->tcp_port;
  KadBuddyInfo info{
      .contact = buddy_contact,
      .buddy_id = response->buddy_id,
      .user_hash = response->user_hash,
      .connect_options = response->has_connect_options ? response->connect_options : std::uint8_t{0},
  };
  buddy_ = info;
  buddy_state_ = KadBuddyState::active;
  co_return info;
}

asio::awaitable<tl::expected<void, std::error_code>>
KadNetwork::send_callback(const Contact& buddy_contact, KadID buddy_id, KadID file_id) {
  auto sent = co_await send_kad_packet(buddy_contact,
                                      encode_kademlia_callback_req(buddy_id, file_id, self_.tcp_port));
  if (!sent) {
    co_return tl::unexpected(sent.error());
  }
  co_return tl::expected<void, std::error_code>{};
}

asio::awaitable<tl::expected<void, std::error_code>>
KadNetwork::serve_once(std::chrono::milliseconds timeout) {
  auto received = co_await recv_kad_packet(timeout);
  if (!received) {
    co_return tl::unexpected(received.error());
  }

  const auto& packet = received->packet;
  const auto& sender = received->sender;
  if (packet.protocol != kad_protocol) {
    co_return protocol_error();
  }

  switch (packet.opcode) {
    case opcode::kad2_bootstrap_req: {
      auto request = decode_kad2_bootstrap_req(packet);
      if (!request) {
        co_return tl::unexpected(request.error());
      }
      auto contacts = routing_.all_contacts();
      if (contacts.size() > 20) {
        contacts.resize(20);
      }
      auto sent = co_await send_kad_packet(sender, encode_kad2_bootstrap_res(self_, contacts),
                                           received->sender_verify_key);
      if (!sent) {
        co_return tl::unexpected(sent.error());
      }
      break;
    }
    case opcode::kad2_bootstrap_res: {
      auto response = decode_kad2_bootstrap_res(packet, endpoint_ip(sender), sender.port());
      if (!response) {
        co_return tl::unexpected(response.error());
      }
      routing_.add_or_update(response->sender);
      for (const auto& contact : response->contacts) {
        routing_.add_or_update(contact);
      }
      break;
    }
    case opcode::kad2_hello_req: {
      auto contact = decode_kad2_hello(packet, endpoint_ip(sender), sender.port());
      if (!contact) {
        co_return tl::unexpected(contact.error());
      }
      routing_.add_or_update(*contact);

      auto response_endpoint = udp::endpoint(sender.address(), contact->udp_port);
      auto sent = co_await send_kad_packet(response_endpoint, encode_kad2_hello_res(self_),
                                           received->sender_verify_key);
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
      auto sent = co_await send_kad_packet(sender, encode_kad2_res(request->target, contacts),
                                           received->sender_verify_key);
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
      auto sent = co_await send_kad_packet(sender, encode_kad2_search_res(self_.id, request->target, entries),
                                           received->sender_verify_key);
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
      auto sent = co_await send_kad_packet(sender, encode_kad2_search_res(self_.id, request->target, entries),
                                           received->sender_verify_key);
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
      auto sent = co_await send_kad_packet(sender, encode_kad2_search_res(self_.id, request->target, entries),
                                           received->sender_verify_key);
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
      auto sent = co_await send_kad_packet(sender, encode_kad2_publish_res(request->key_id, 0),
                                           received->sender_verify_key);
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
      auto source = std::move(request->source);
      if (source_type(source) != 0) {
        if (!has_tag(source, tag::source_ip)) {
          source.tags.push_back(int_tag(tag::source_ip, endpoint_ip(sender).host()));
        }
        if (!has_tag(source, tag::source_udp_port)) {
          source.tags.push_back(int_tag(tag::source_udp_port, sender.port()));
        }
      }
      indexed_.add_source(request->file_id, std::move(source));
      auto sent = co_await send_kad_packet(sender, encode_kad2_publish_res(request->file_id, 0),
                                           received->sender_verify_key);
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
      auto sent = co_await send_kad_packet(sender, encode_kad2_publish_res(request->file_id, 0),
                                           received->sender_verify_key);
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
    case opcode::kademlia_firewalled_req: {
      auto request = decode_kademlia_firewalled_req(packet);
      if (!request) {
        co_return tl::unexpected(request.error());
      }
      auto sent = co_await send_kad_packet(sender, encode_kademlia_firewalled_res(endpoint_ip(sender)),
                                           received->sender_verify_key);
      if (!sent) {
        co_return tl::unexpected(sent.error());
      }
      break;
    }
    case opcode::kademlia_firewalled2_req: {
      auto request = decode_kademlia_firewalled2_req(packet);
      if (!request) {
        co_return tl::unexpected(request.error());
      }
      auto sent = co_await send_kad_packet(sender, encode_kademlia_firewalled_res(endpoint_ip(sender)),
                                           received->sender_verify_key);
      if (!sent) {
        co_return tl::unexpected(sent.error());
      }
      break;
    }
    case opcode::kademlia_firewalled_res: {
      auto response = decode_kademlia_firewalled_res(packet);
      if (!response) {
        co_return tl::unexpected(response.error());
      }
      observed_external_ip_ = response->ip;
      break;
    }
    case opcode::kademlia_firewalled_ack_res: {
      auto ack = decode_kademlia_firewalled_ack_res(packet);
      if (!ack) {
        co_return tl::unexpected(ack.error());
      }
      break;
    }
    case opcode::kad2_firewall_udp: {
      auto result = decode_kad2_firewall_udp(packet);
      if (!result) {
        co_return tl::unexpected(result.error());
      }

      const bool reachable = result->error_code == 0 && result->incoming_port == self_.udp_port;
      last_udp_firewall_result_ = KadFirewallUdpResult{
          .error_code = result->error_code,
          .incoming_port = result->incoming_port,
          .sender_ip = endpoint_ip(sender),
          .reachable = reachable,
          .remote_error = !reachable,
      };
      udp_firewall_state_ = reachable ? KadFirewallState::open : KadFirewallState::firewalled;
      break;
    }
    case opcode::kademlia_find_buddy_req: {
      auto request = decode_kademlia_find_buddy_req(packet);
      if (!request) {
        co_return tl::unexpected(request.error());
      }
      if (buddy_state_ == KadBuddyState::active) {
        co_return tl::expected<void, std::error_code>{};
      }

      Contact firewalled_contact{
          .id = bitwise_not_id(request->buddy_id),
          .ip = endpoint_ip(sender),
          .udp_port = sender.port(),
          .tcp_port = request->tcp_port,
          .version = kad2_version,
      };
      buddy_ = KadBuddyInfo{
          .contact = firewalled_contact,
          .buddy_id = request->buddy_id,
          .user_hash = request->user_hash,
          .connect_options = request->has_connect_options ? request->connect_options : std::uint8_t{0},
      };
      buddy_state_ = KadBuddyState::active;

      auto sent = co_await send_kad_packet(sender,
                                          encode_kademlia_find_buddy_res(request->buddy_id, user_hash_,
                                                                         self_.tcp_port),
                                          received->sender_verify_key);
      if (!sent) {
        co_return tl::unexpected(sent.error());
      }
      break;
    }
    case opcode::kademlia_find_buddy_res: {
      auto response = decode_kademlia_find_buddy_res(packet);
      if (!response) {
        co_return tl::unexpected(response.error());
      }
      break;
    }
    case opcode::kademlia_callback_req: {
      auto request = decode_kademlia_callback_req(packet);
      if (!request) {
        co_return tl::unexpected(request.error());
      }
      last_callback_ = KadCallbackEvent{
          .buddy_id = request->buddy_id,
          .file_id = request->file_id,
          .requester_ip = endpoint_ip(sender),
          .requester_tcp_port = request->tcp_port,
      };
      break;
    }
    default:
      co_return protocol_error();
  }

  co_return tl::expected<void, std::error_code>{};
}

} // namespace ed2k::kad
