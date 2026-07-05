#include "ed2k/kad/indexed.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace ed2k::kad {

KadIndexed::KadIndexed(clock::duration ttl) : ttl_(ttl) {}

void KadIndexed::add_keyword(const KadID& key_id, KadSearchEntry entry, clock::time_point now) {
  add(keywords_, key_id, std::move(entry), now);
}

void KadIndexed::add_source(const KadID& file_id, KadSearchEntry source, clock::time_point now) {
  add(sources_, file_id, std::move(source), now);
}

void KadIndexed::add_note(const KadID& file_id, KadSearchEntry note, clock::time_point now) {
  add(notes_, file_id, std::move(note), now);
}

std::vector<KadSearchEntry> KadIndexed::search_keyword(const KadID& key_id, std::size_t max_results,
                                                       clock::time_point now) {
  return search(keywords_, key_id, max_results, now);
}

std::vector<KadSearchEntry> KadIndexed::search_sources(const KadID& file_id,
                                                       std::uint64_t requested_file_size,
                                                       std::size_t max_results,
                                                       clock::time_point now) {
  auto results = search(sources_, file_id, std::numeric_limits<std::size_t>::max(), now);
  if (requested_file_size != 0) {
    results.erase(std::remove_if(results.begin(), results.end(), [&](const KadSearchEntry& entry) {
                    const auto indexed_size = file_size(entry);
                    return indexed_size != 0 && indexed_size != requested_file_size;
                  }),
                  results.end());
  }
  if (results.size() > max_results) {
    results.resize(max_results);
  }
  return results;
}

std::vector<KadSearchEntry> KadIndexed::search_notes(const KadID& file_id,
                                                     std::uint64_t requested_file_size,
                                                     std::size_t max_results,
                                                     clock::time_point now) {
  auto results = search(notes_, file_id, std::numeric_limits<std::size_t>::max(), now);
  if (requested_file_size != 0) {
    results.erase(std::remove_if(results.begin(), results.end(), [&](const KadSearchEntry& entry) {
                    const auto indexed_size = file_size(entry);
                    return indexed_size != 0 && indexed_size != requested_file_size;
                  }),
                  results.end());
  }
  if (results.size() > max_results) {
    results.resize(max_results);
  }
  return results;
}

void KadIndexed::clean(clock::time_point now) {
  const auto clean_map = [&](EntryMap& map) {
    for (auto it = map.begin(); it != map.end();) {
      auto& entries = it->second;
      entries.erase(std::remove_if(entries.begin(), entries.end(), [&](const StoredEntry& entry) {
                      return entry.expires_at <= now;
                    }),
                    entries.end());
      if (entries.empty()) {
        it = map.erase(it);
      } else {
        ++it;
      }
    }
  };
  clean_map(keywords_);
  clean_map(sources_);
  clean_map(notes_);
}

void KadIndexed::add(EntryMap& map, const KadID& key, KadSearchEntry entry, clock::time_point now) {
  auto& entries = map[key];
  const auto existing = std::find_if(entries.begin(), entries.end(), [&](const StoredEntry& current) {
    return current.entry.answer_id == entry.answer_id;
  });
  StoredEntry stored{.entry = std::move(entry), .expires_at = now + ttl_};
  if (existing != entries.end()) {
    *existing = std::move(stored);
    return;
  }
  entries.push_back(std::move(stored));
}

std::vector<KadSearchEntry> KadIndexed::search(EntryMap& map, const KadID& key, std::size_t max_results,
                                               clock::time_point now) {
  clean(now);
  const auto found = map.find(key);
  if (found == map.end() || max_results == 0) {
    return {};
  }

  std::vector<KadSearchEntry> out;
  out.reserve(std::min(max_results, found->second.size()));
  for (const auto& stored : found->second) {
    if (out.size() >= max_results) {
      break;
    }
    out.push_back(stored.entry);
  }
  return out;
}

} // namespace ed2k::kad
