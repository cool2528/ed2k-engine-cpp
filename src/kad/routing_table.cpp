#include "ed2k/kad/routing_table.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace ed2k::kad {

bool KBucket::add_or_update(Contact contact) {
  const auto existing = std::find_if(contacts_.begin(), contacts_.end(), [&](const Contact& current) {
    return current.id == contact.id;
  });
  if (existing != contacts_.end()) {
    contacts_.erase(existing);
    contacts_.push_back(std::move(contact));
    return true;
  }

  if (full()) {
    return false;
  }

  contacts_.push_back(std::move(contact));
  return true;
}

bool KBucket::remove(const KadID& id) noexcept {
  const auto existing = std::find_if(contacts_.begin(), contacts_.end(), [&](const Contact& current) {
    return current.id == id;
  });
  if (existing == contacts_.end()) {
    return false;
  }
  contacts_.erase(existing);
  return true;
}

const Contact* KBucket::find(const KadID& id) const noexcept {
  const auto existing = std::find_if(contacts_.begin(), contacts_.end(), [&](const Contact& current) {
    return current.id == id;
  });
  return existing == contacts_.end() ? nullptr : &*existing;
}

std::vector<Contact> KBucket::take_contacts() {
  std::vector<Contact> out;
  out.swap(contacts_);
  return out;
}

struct RoutingZone::Node {
  explicit Node(std::size_t depth_in, bool contains_self_in)
      : depth(depth_in), contains_self(contains_self_in) {}

  bool leaf() const noexcept { return !children[0] && !children[1]; }

  std::size_t depth = 0;
  bool contains_self = false;
  KBucket bucket;
  std::array<std::unique_ptr<Node>, 2> children{};
};

namespace {
void split_node(RoutingZone::Node& node, const KadID& self_id) {
  node.children[0] = std::make_unique<RoutingZone::Node>(
      node.depth + 1, node.contains_self && self_id.bit(node.depth) == 0);
  node.children[1] = std::make_unique<RoutingZone::Node>(
      node.depth + 1, node.contains_self && self_id.bit(node.depth) == 1);

  auto contacts = node.bucket.take_contacts();
  for (auto& contact : contacts) {
    const auto side = contact.id.bit(node.depth);
    node.children[side]->bucket.add_or_update(std::move(contact));
  }
}

bool add_to_node(RoutingZone::Node& node, const KadID& self_id, Contact contact) {
  if (!node.leaf()) {
    return add_to_node(*node.children[contact.id.bit(node.depth)], self_id, std::move(contact));
  }

  if (node.bucket.find(contact.id) != nullptr || !node.bucket.full()) {
    return node.bucket.add_or_update(std::move(contact));
  }

  if (node.contains_self && node.depth < KadID::size * 8) {
    split_node(node, self_id);
    return add_to_node(*node.children[contact.id.bit(node.depth)], self_id, std::move(contact));
  }

  return false;
}

std::size_t node_size(const RoutingZone::Node& node) noexcept {
  if (node.leaf()) {
    return node.bucket.size();
  }
  return node_size(*node.children[0]) + node_size(*node.children[1]);
}

std::size_t count_leaves(const RoutingZone::Node& node) noexcept {
  if (node.leaf()) {
    return 1;
  }
  return count_leaves(*node.children[0]) + count_leaves(*node.children[1]);
}

void collect_contacts(const RoutingZone::Node& node, std::vector<Contact>& out) {
  if (node.leaf()) {
    out.insert(out.end(), node.bucket.contacts().begin(), node.bucket.contacts().end());
    return;
  }
  collect_contacts(*node.children[0], out);
  collect_contacts(*node.children[1], out);
}

void consolidate_node(RoutingZone::Node& node) {
  if (node.leaf()) {
    return;
  }

  if (!node.children[0]->leaf() || !node.children[1]->leaf()) {
    return;
  }

  const auto combined_size = node.children[0]->bucket.size() + node.children[1]->bucket.size();
  if (combined_size > KBucket::capacity / 2) {
    return;
  }

  std::vector<Contact> merged;
  collect_contacts(*node.children[0], merged);
  collect_contacts(*node.children[1], merged);
  node.children[0].reset();
  node.children[1].reset();
  for (auto& contact : merged) {
    node.bucket.add_or_update(std::move(contact));
  }
}

bool remove_from_node(RoutingZone::Node& node, const KadID& id) {
  if (node.leaf()) {
    return node.bucket.remove(id);
  }

  const auto removed = remove_from_node(*node.children[id.bit(node.depth)], id);
  if (removed) {
    consolidate_node(*node.children[0]);
    consolidate_node(*node.children[1]);
    consolidate_node(node);
  }
  return removed;
}

const Contact* find_in_node(const RoutingZone::Node& node, const KadID& id) noexcept {
  if (node.leaf()) {
    return node.bucket.find(id);
  }
  return find_in_node(*node.children[id.bit(node.depth)], id);
}
} // namespace

RoutingZone::RoutingZone(KadID self_id)
    : self_id_(self_id), root_(std::make_unique<Node>(0, true)) {}

RoutingZone::~RoutingZone() = default;
RoutingZone::RoutingZone(RoutingZone&&) noexcept = default;
RoutingZone& RoutingZone::operator=(RoutingZone&&) noexcept = default;

bool RoutingZone::add_or_update(Contact contact) {
  if (contact.id == self_id_) {
    return false;
  }
  return add_to_node(*root_, self_id_, std::move(contact));
}

bool RoutingZone::remove(const KadID& id) {
  return remove_from_node(*root_, id);
}

const Contact* RoutingZone::find(const KadID& id) const noexcept {
  return find_in_node(*root_, id);
}

std::size_t RoutingZone::size() const noexcept {
  return node_size(*root_);
}

std::size_t RoutingZone::leaf_count() const noexcept {
  return count_leaves(*root_);
}

std::vector<Contact> RoutingZone::all_contacts() const {
  std::vector<Contact> out;
  out.reserve(size());
  collect_contacts(*root_, out);
  return out;
}

RoutingTable::RoutingTable(KadID self_id) : zone_(self_id) {}

bool RoutingTable::add_or_update(Contact contact) {
  return zone_.add_or_update(std::move(contact));
}

bool RoutingTable::remove(const KadID& id) {
  return zone_.remove(id);
}

const Contact* RoutingTable::find(const KadID& id) const noexcept {
  return zone_.find(id);
}

std::size_t RoutingTable::size() const noexcept {
  return zone_.size();
}

std::size_t RoutingTable::leaf_count() const noexcept {
  return zone_.leaf_count();
}

std::vector<Contact> RoutingTable::all_contacts() const {
  return zone_.all_contacts();
}

std::vector<Contact> RoutingTable::closest_to(const KadID& target, std::size_t max_results) const {
  auto contacts = all_contacts();
  std::sort(contacts.begin(), contacts.end(), [&](const Contact& lhs, const Contact& rhs) {
    const auto lhs_distance = xor_distance(lhs.id, target);
    const auto rhs_distance = xor_distance(rhs.id, target);
    if (lhs_distance == rhs_distance) {
      return lhs.id < rhs.id;
    }
    return lhs_distance < rhs_distance;
  });
  if (contacts.size() > max_results) {
    contacts.resize(max_results);
  }
  return contacts;
}

const KadID& RoutingTable::self_id() const noexcept {
  return zone_.self_id();
}

} // namespace ed2k::kad
