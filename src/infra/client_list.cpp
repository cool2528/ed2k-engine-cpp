#include "ed2k/infra/client_list.hpp"

#include <algorithm>

namespace ed2k::infra {

ClientList::ClientList(std::chrono::seconds stale_after)
  : stale_after_(stale_after) {}

void ClientList::upsert(const UserHash& user_hash,
                        IPv4 ip,
                        std::uint16_t port,
                        std::chrono::system_clock::time_point now) {
  auto it = by_hash_.find(user_hash);
  if (it == by_hash_.end()) {
    by_hash_.emplace(user_hash, entries_.size());
    entries_.push_back({user_hash, ip, port, now});
    return;
  }

  auto& entry = entries_[it->second];
  entry.ip = ip;
  entry.port = port;
  entry.last_seen = now;
}

const ClientEntry* ClientList::find(const UserHash& user_hash) const {
  auto it = by_hash_.find(user_hash);
  if (it == by_hash_.end()) {
    return nullptr;
  }
  return &entries_[it->second];
}

std::vector<ClientEntry> ClientList::cleanup(std::chrono::system_clock::time_point now) {
  std::vector<ClientEntry> removed;
  auto keep = [&](const ClientEntry& entry) {
    if (now - entry.last_seen > stale_after_) {
      removed.push_back(entry);
      return false;
    }
    return true;
  };
  entries_.erase(std::remove_if(entries_.begin(), entries_.end(), [&](const ClientEntry& entry) {
                   return !keep(entry);
                 }),
                 entries_.end());
  rebuild_index();
  return removed;
}

std::optional<peer::PeerSource> ClientList::source_for(const UserHash& user_hash) const {
  const auto* entry = find(user_hash);
  if (!entry) {
    return std::nullopt;
  }

  peer::PeerSource source;
  source.client_id = entry->ip.host();
  source.port = entry->port;
  source.user_hash = entry->user_hash;
  return source;
}

std::vector<peer::PeerSource> ClientList::sources_for(std::span<const UserHash> user_hashes) const {
  std::vector<peer::PeerSource> out;
  out.reserve(user_hashes.size());
  for (const auto& user_hash : user_hashes) {
    if (auto source = source_for(user_hash)) {
      out.push_back(*source);
    }
  }
  return out;
}

bool ClientList::attach_source(ed2k::share::KnownFileDB& db,
                               const FileHash& file_hash,
                               const UserHash& user_hash) const {
  auto source = source_for(user_hash);
  if (!source) {
    return false;
  }
  return db.add_source(file_hash, *source);
}

void ClientList::rebuild_index() {
  by_hash_.clear();
  for (std::size_t i = 0; i < entries_.size(); ++i) {
    by_hash_.emplace(entries_[i].user_hash, i);
  }
}

} // namespace ed2k::infra
