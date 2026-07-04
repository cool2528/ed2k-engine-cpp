#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include "ed2k/core/hash.hpp"
#include "ed2k/share/client_credits.hpp"

namespace ed2k::share {

enum class UploadQueueState {
  accepted,
  queued
};

struct UploadQueueDecision {
  UploadQueueState state = UploadQueueState::queued;
  std::uint16_t rank = 0;
};

struct UploadQueueGrant {
  UserHash user_hash;
  FileHash file_hash;
};

class UploadQueue {
 public:
  explicit UploadQueue(std::size_t max_slots, const ClientCredits* credits = nullptr);

  UploadQueueDecision enqueue(const UserHash& user_hash, const FileHash& file_hash);
  std::vector<UploadQueueGrant> tick();
  void release(const UserHash& user_hash);
  void remove(const UserHash& user_hash);
  bool has_slot(const UserHash& user_hash) const;
  std::uint16_t rank(const UserHash& user_hash) const;

 private:
  struct Entry {
    UserHash user_hash;
    FileHash file_hash;
  };

  std::size_t max_slots_ = 0;
  const ClientCredits* credits_ = nullptr;
  std::vector<Entry> active_;
  std::vector<Entry> queued_;
};

} // namespace ed2k::share
