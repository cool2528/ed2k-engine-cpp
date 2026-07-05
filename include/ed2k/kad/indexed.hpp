#pragma once

#include <chrono>
#include <cstddef>
#include <unordered_map>
#include <vector>

#include "ed2k/kad/messages.hpp"

namespace ed2k::kad {

class KadIndexed {
 public:
  using clock = std::chrono::steady_clock;

  explicit KadIndexed(clock::duration ttl = std::chrono::hours(24));

  void add_keyword(const KadID& key_id, KadSearchEntry entry, clock::time_point now = clock::now());
  void add_source(const KadID& file_id, KadSearchEntry source, clock::time_point now = clock::now());
  void add_note(const KadID& file_id, KadSearchEntry note, clock::time_point now = clock::now());

  std::vector<KadSearchEntry> search_keyword(const KadID& key_id, std::size_t max_results,
                                             clock::time_point now = clock::now());
  std::vector<KadSearchEntry> search_sources(const KadID& file_id, std::uint64_t requested_file_size,
                                             std::size_t max_results,
                                             clock::time_point now = clock::now());
  std::vector<KadSearchEntry> search_notes(const KadID& file_id, std::uint64_t requested_file_size,
                                           std::size_t max_results,
                                           clock::time_point now = clock::now());

  void clean(clock::time_point now = clock::now());

 private:
  struct StoredEntry {
    KadSearchEntry entry;
    clock::time_point expires_at;
  };

  using EntryMap = std::unordered_map<KadID, std::vector<StoredEntry>>;

  void add(EntryMap& map, const KadID& key, KadSearchEntry entry, clock::time_point now);
  std::vector<KadSearchEntry> search(EntryMap& map, const KadID& key, std::size_t max_results,
                                     clock::time_point now);

  clock::duration ttl_;
  EntryMap keywords_;
  EntryMap sources_;
  EntryMap notes_;
};

} // namespace ed2k::kad
