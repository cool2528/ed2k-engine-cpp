#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <tl/expected.hpp>

#include "ed2k/codec/tag.hpp"
#include "ed2k/kad/routing_table.hpp"
#include "ed2k/net/packet.hpp"

namespace ed2k::kad {

inline constexpr std::uint8_t kad_protocol = 0xE4;
inline constexpr std::uint8_t kad_packed_protocol = 0xE5;
inline constexpr std::uint8_t kad2_version = 0x08;

namespace tag {
inline constexpr std::uint8_t filename = 0x01;
inline constexpr std::uint8_t file_size = 0x02;
inline constexpr std::uint8_t file_type = 0x03;
inline constexpr std::uint8_t description = 0x0B;
inline constexpr std::uint8_t sources = 0x15;
inline constexpr std::uint8_t file_rating = 0xF7;
inline constexpr std::uint8_t source_udp_port = 0xFC;
inline constexpr std::uint8_t source_port = 0xFD;
inline constexpr std::uint8_t source_ip = 0xFE;
inline constexpr std::uint8_t source_type = 0xFF;
} // namespace tag

namespace opcode {
inline constexpr std::uint8_t kad2_bootstrap_req = 0x01;
inline constexpr std::uint8_t kad2_bootstrap_res = 0x09;
inline constexpr std::uint8_t kad2_hello_req = 0x11;
inline constexpr std::uint8_t kad2_hello_res = 0x19;
inline constexpr std::uint8_t kad2_req = 0x21;
inline constexpr std::uint8_t kad2_hello_res_ack = 0x22;
inline constexpr std::uint8_t kad2_res = 0x29;
inline constexpr std::uint8_t kad2_search_key_req = 0x33;
inline constexpr std::uint8_t kad2_search_source_req = 0x34;
inline constexpr std::uint8_t kad2_search_notes_req = 0x35;
inline constexpr std::uint8_t kad2_search_res = 0x3B;
inline constexpr std::uint8_t kad2_publish_key_req = 0x43;
inline constexpr std::uint8_t kad2_publish_source_req = 0x44;
inline constexpr std::uint8_t kad2_publish_notes_req = 0x45;
inline constexpr std::uint8_t kad2_publish_res = 0x4B;
inline constexpr std::uint8_t kad2_publish_res_ack = 0x4C;
inline constexpr std::uint8_t kademlia_firewalled_req = 0x50;
inline constexpr std::uint8_t kademlia_find_buddy_req = 0x51;
inline constexpr std::uint8_t kademlia_callback_req = 0x52;
inline constexpr std::uint8_t kademlia_firewalled2_req = 0x53;
inline constexpr std::uint8_t kademlia_firewalled_res = 0x58;
inline constexpr std::uint8_t kademlia_firewalled_ack_res = 0x59;
inline constexpr std::uint8_t kademlia_find_buddy_res = 0x5A;
inline constexpr std::uint8_t kad2_ping = 0x60;
inline constexpr std::uint8_t kad2_pong = 0x61;
inline constexpr std::uint8_t kad2_firewall_udp = 0x62;
} // namespace opcode

struct Kad2Request {
  std::uint8_t count = 0;
  KadID target;
  KadID receiver_id;
};

struct Kad2Response {
  KadID target;
  std::vector<Contact> contacts;
};

struct KadSearchRequest {
  KadID target;
  std::uint16_t start_position = 0;
  std::uint64_t file_size = 0;
};

struct KadSearchEntry {
  KadID answer_id;
  std::vector<codec::Tag> tags;
};

struct KadSearchResponse {
  KadID sender_id;
  KadID target;
  std::vector<KadSearchEntry> entries;
};

struct KadPublishKeyRequest {
  KadID key_id;
  std::vector<KadSearchEntry> entries;
};

struct KadPublishSourceRequest {
  KadID file_id;
  KadSearchEntry source;
};

struct KadPublishNotesRequest {
  KadID file_id;
  KadSearchEntry note;
};

struct KadPublishResponse {
  KadID target;
  std::uint8_t load = 0;
  bool requests_ack = false;
};

struct KadFirewalledRequest {
  std::uint16_t tcp_port = 0;
  KadID user_hash;
  std::uint8_t connect_options = 0;
  bool has_user_hash = false;
};

struct KadFirewalledResponse {
  IPv4 ip;
};

struct KadFirewallUdp {
  std::uint8_t error_code = 0;
  std::uint16_t incoming_port = 0;
};

struct KadBuddyMessage {
  KadID buddy_id;
  KadID user_hash;
  std::uint16_t tcp_port = 0;
  std::uint8_t connect_options = 0;
  bool has_connect_options = false;
};

struct KadCallbackRequest {
  KadID buddy_id;
  KadID file_id;
  std::uint16_t tcp_port = 0;
};

net::Packet encode_kad2_hello_req(const Contact& self);
net::Packet encode_kad2_hello_res(const Contact& self);
tl::expected<Contact, std::error_code> decode_kad2_hello(const net::Packet& packet,
                                                          IPv4 sender_ip,
                                                          std::uint16_t sender_udp_port);

net::Packet encode_kad2_req(const KadID& target, const KadID& receiver_id, std::uint8_t count);
tl::expected<Kad2Request, std::error_code> decode_kad2_req(const net::Packet& packet);

net::Packet encode_kad2_res(const KadID& target, std::span<const Contact> contacts);
tl::expected<Kad2Response, std::error_code> decode_kad2_res(const net::Packet& packet);

net::Packet encode_kad2_search_key_req(const KadID& target, std::uint16_t start_position);
tl::expected<KadSearchRequest, std::error_code> decode_kad2_search_key_req(const net::Packet& packet);

net::Packet encode_kad2_search_source_req(const KadID& target, std::uint16_t start_position,
                                           std::uint64_t file_size);
tl::expected<KadSearchRequest, std::error_code> decode_kad2_search_source_req(const net::Packet& packet);

net::Packet encode_kad2_search_notes_req(const KadID& target, std::uint64_t file_size);
tl::expected<KadSearchRequest, std::error_code> decode_kad2_search_notes_req(const net::Packet& packet);

net::Packet encode_kad2_search_res(const KadID& sender_id, const KadID& target,
                                    std::span<const KadSearchEntry> entries);
tl::expected<KadSearchResponse, std::error_code> decode_kad2_search_res(const net::Packet& packet);

net::Packet encode_kad2_publish_key_req(const KadID& key_id, std::span<const KadSearchEntry> entries);
tl::expected<KadPublishKeyRequest, std::error_code> decode_kad2_publish_key_req(const net::Packet& packet);

net::Packet encode_kad2_publish_source_req(const KadID& file_id, const KadSearchEntry& source);
tl::expected<KadPublishSourceRequest, std::error_code> decode_kad2_publish_source_req(const net::Packet& packet);

net::Packet encode_kad2_publish_notes_req(const KadID& file_id, const KadSearchEntry& note);
tl::expected<KadPublishNotesRequest, std::error_code> decode_kad2_publish_notes_req(const net::Packet& packet);

net::Packet encode_kad2_publish_res(const KadID& target, std::uint8_t load);
tl::expected<KadPublishResponse, std::error_code> decode_kad2_publish_res(const net::Packet& packet);

net::Packet encode_kademlia_firewalled_req(std::uint16_t tcp_port);
tl::expected<KadFirewalledRequest, std::error_code> decode_kademlia_firewalled_req(const net::Packet& packet);

net::Packet encode_kademlia_firewalled2_req(std::uint16_t tcp_port, const KadID& user_hash,
                                             std::uint8_t connect_options);
tl::expected<KadFirewalledRequest, std::error_code> decode_kademlia_firewalled2_req(const net::Packet& packet);

net::Packet encode_kademlia_firewalled_res(IPv4 ip);
tl::expected<KadFirewalledResponse, std::error_code> decode_kademlia_firewalled_res(const net::Packet& packet);

net::Packet encode_kademlia_firewalled_ack_res();
tl::expected<void, std::error_code> decode_kademlia_firewalled_ack_res(const net::Packet& packet);

net::Packet encode_kad2_firewall_udp(std::uint8_t error_code, std::uint16_t incoming_port);
tl::expected<KadFirewallUdp, std::error_code> decode_kad2_firewall_udp(const net::Packet& packet);

net::Packet encode_kademlia_find_buddy_req(const KadID& buddy_id, const KadID& user_hash,
                                            std::uint16_t tcp_port);
net::Packet encode_kademlia_find_buddy_res(const KadID& buddy_id, const KadID& user_hash,
                                            std::uint16_t tcp_port);
net::Packet encode_kademlia_find_buddy_res(const KadID& buddy_id, const KadID& user_hash,
                                            std::uint16_t tcp_port, std::uint8_t connect_options);
tl::expected<KadBuddyMessage, std::error_code> decode_kademlia_find_buddy_req(const net::Packet& packet);
tl::expected<KadBuddyMessage, std::error_code> decode_kademlia_find_buddy_res(const net::Packet& packet);

net::Packet encode_kademlia_callback_req(const KadID& buddy_id, const KadID& file_id,
                                          std::uint16_t tcp_port);
tl::expected<KadCallbackRequest, std::error_code> decode_kademlia_callback_req(const net::Packet& packet);

std::string file_name(const KadSearchEntry& entry);
std::uint64_t file_size(const KadSearchEntry& entry) noexcept;
std::uint16_t source_tcp_port(const KadSearchEntry& entry) noexcept;
std::uint16_t source_udp_port(const KadSearchEntry& entry) noexcept;

} // namespace ed2k::kad
