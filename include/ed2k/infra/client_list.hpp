#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "ed2k/core/hash.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/share/known_file.hpp"

namespace ed2k::infra {

struct ClientEntry {
  UserHash user_hash;
  IPv4 ip;
  std::uint16_t port = 0;
  std::chrono::system_clock::time_point last_seen{};
};

class ClientList {
 public:
  explicit ClientList(std::chrono::seconds stale_after = std::chrono::minutes(30));

  void upsert(const UserHash& user_hash,
              IPv4 ip,
              std::uint16_t port,
              std::chrono::system_clock::time_point now);
  const ClientEntry* find(const UserHash& user_hash) const;
  std::vector<ClientEntry> cleanup(std::chrono::system_clock::time_point now);
  std::optional<peer::PeerSource> source_for(const UserHash& user_hash) const;
  std::vector<peer::PeerSource> sources_for(std::span<const UserHash> user_hashes) const;
  bool attach_source(ed2k::share::KnownFileDB& db,
                     const FileHash& file_hash,
                     const UserHash& user_hash) const;

  const std::vector<ClientEntry>& entries() const noexcept { return entries_; }

 private:
  void rebuild_index();

  std::chrono::seconds stale_after_;
  std::vector<ClientEntry> entries_;
  std::unordered_map<UserHash, std::size_t> by_hash_;
};

} // namespace ed2k::infra
