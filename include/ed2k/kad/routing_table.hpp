#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "ed2k/core/hash.hpp"
#include "ed2k/kad/kad_id.hpp"

namespace ed2k::kad {

struct Contact {
  KadID id;
  IPv4 ip;
  std::uint16_t udp_port = 0;
  std::uint16_t tcp_port = 0;
  std::uint8_t version = 0;

  auto operator<=>(const Contact&) const = default;
};

class KBucket {
 public:
  static constexpr std::size_t capacity = 10;

  bool add_or_update(Contact contact);
  bool remove(const KadID& id) noexcept;
  const Contact* find(const KadID& id) const noexcept;
  std::size_t size() const noexcept { return contacts_.size(); }
  bool full() const noexcept { return contacts_.size() >= capacity; }
  const std::vector<Contact>& contacts() const noexcept { return contacts_; }
  std::vector<Contact> take_contacts();

 private:
  std::vector<Contact> contacts_;
};

class RoutingZone {
 public:
  struct Node;

  explicit RoutingZone(KadID self_id);
  ~RoutingZone();

  RoutingZone(RoutingZone&&) noexcept;
  RoutingZone& operator=(RoutingZone&&) noexcept;
  RoutingZone(const RoutingZone&) = delete;
  RoutingZone& operator=(const RoutingZone&) = delete;

  bool add_or_update(Contact contact);
  bool remove(const KadID& id);
  std::size_t size() const noexcept;
  std::size_t leaf_count() const noexcept;
  std::vector<Contact> all_contacts() const;
  const KadID& self_id() const noexcept { return self_id_; }

 private:
  KadID self_id_;
  std::unique_ptr<Node> root_;
};

class RoutingTable {
 public:
  explicit RoutingTable(KadID self_id);

  bool add_or_update(Contact contact);
  bool remove(const KadID& id);
  std::size_t size() const noexcept;
  std::size_t leaf_count() const noexcept;
  std::vector<Contact> all_contacts() const;
  std::vector<Contact> closest_to(const KadID& target, std::size_t max_results) const;
  const KadID& self_id() const noexcept;

 private:
  RoutingZone zone_;
};

} // namespace ed2k::kad
