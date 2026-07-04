#include "ed2k/share/upload_queue.hpp"
#include <algorithm>

namespace ed2k::share {

UploadQueue::UploadQueue(std::size_t max_slots) : max_slots_(max_slots) {}

UploadQueueDecision UploadQueue::enqueue(const UserHash& user_hash, const FileHash& file_hash) {
  if(has_slot(user_hash)) return {UploadQueueState::accepted, 0};
  const auto queued_it = std::find_if(queued_.begin(), queued_.end(), [&](const Entry& e) {
    return e.user_hash == user_hash;
  });
  if(queued_it != queued_.end()) {
    if(active_.size() < max_slots_ && queued_it == queued_.begin()) {
      Entry entry = *queued_it;
      queued_.erase(queued_it);
      active_.push_back(entry);
      return {UploadQueueState::accepted, 0};
    }
    return {UploadQueueState::queued,
            static_cast<std::uint16_t>(std::distance(queued_.begin(), queued_it) + 1)};
  }

  Entry entry{user_hash, file_hash};
  if(active_.size() < max_slots_ && queued_.empty()) {
    active_.push_back(entry);
    return {UploadQueueState::accepted, 0};
  }

  queued_.push_back(entry);
  return {UploadQueueState::queued, static_cast<std::uint16_t>(queued_.size())};
}

std::vector<UploadQueueGrant> UploadQueue::tick() {
  std::vector<UploadQueueGrant> grants;
  while(active_.size() < max_slots_ && !queued_.empty()) {
    Entry entry = queued_.front();
    queued_.erase(queued_.begin());
    active_.push_back(entry);
    grants.push_back({entry.user_hash, entry.file_hash});
  }
  return grants;
}

void UploadQueue::release(const UserHash& user_hash) {
  active_.erase(std::remove_if(active_.begin(), active_.end(), [&](const Entry& e) {
    return e.user_hash == user_hash;
  }), active_.end());
}

void UploadQueue::remove(const UserHash& user_hash) {
  release(user_hash);
  queued_.erase(std::remove_if(queued_.begin(), queued_.end(), [&](const Entry& e) {
    return e.user_hash == user_hash;
  }), queued_.end());
}

bool UploadQueue::has_slot(const UserHash& user_hash) const {
  return std::any_of(active_.begin(), active_.end(), [&](const Entry& e) {
    return e.user_hash == user_hash;
  });
}

std::uint16_t UploadQueue::rank(const UserHash& user_hash) const {
  for(std::size_t i = 0; i < queued_.size(); ++i) {
    if(queued_[i].user_hash == user_hash) return static_cast<std::uint16_t>(i + 1);
  }
  return 0;
}

} // namespace ed2k::share
