#include "ed2k/share/client_credits.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::share {
namespace {
constexpr std::uint8_t CLIENT_CREDITS_MAGIC = 0x12;
constexpr std::uint8_t CLIENT_CREDITS_VERSION = 1;
constexpr std::int64_t SCORE_BASE = 1000;
constexpr std::uint64_t SCORE_QUANTUM = 1024;
}

std::vector<std::byte> write_client_credits(std::span<const CreditRecord> records) {
  codec::ByteWriter w;
  w.u8(CLIENT_CREDITS_MAGIC);
  w.u8(CLIENT_CREDITS_VERSION);
  w.u32(static_cast<std::uint32_t>(records.size()));
  for(const auto& r : records) {
    w.hash16(r.key);
    w.u64(r.uploaded);
    w.u64(r.downloaded);
  }
  return w.take();
}

tl::expected<std::vector<CreditRecord>, std::error_code>
parse_client_credits(std::span<const std::byte> data) {
  codec::ByteReader r(data);
  const auto magic = r.u8();
  const auto version = r.u8();
  if(magic != CLIENT_CREDITS_MAGIC || version != CLIENT_CREDITS_VERSION)
    return tl::unexpected(make_error_code(errc::bad_magic));
  const auto count = r.u32();
  if(count > 1000000) return tl::unexpected(make_error_code(errc::count_too_large));
  std::vector<CreditRecord> out;
  out.reserve(count);
  for(std::uint32_t i = 0; i < count; ++i) {
    CreditRecord rec;
    rec.key = r.hash16();
    rec.uploaded = r.u64();
    rec.downloaded = r.u64();
    if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
    out.push_back(rec);
  }
  return out;
}

void ClientCredits::add_uploaded(const UserHash& key, std::uint64_t bytes) {
  ensure(key).uploaded += bytes;
}

void ClientCredits::add_downloaded(const UserHash& key, std::uint64_t bytes) {
  ensure(key).downloaded += bytes;
}

std::uint64_t ClientCredits::uploaded(const UserHash& key) const {
  const auto* rec = find(key);
  return rec ? rec->uploaded : 0;
}

std::uint64_t ClientCredits::downloaded(const UserHash& key) const {
  const auto* rec = find(key);
  return rec ? rec->downloaded : 0;
}

std::int64_t ClientCredits::score(const UserHash& key) const {
  const auto* rec = find(key);
  if(!rec) return SCORE_BASE;
  const auto up = static_cast<std::int64_t>(rec->uploaded / SCORE_QUANTUM);
  const auto down = static_cast<std::int64_t>(rec->downloaded / SCORE_QUANTUM);
  return SCORE_BASE + up - down;
}

CreditRecord& ClientCredits::ensure(const UserHash& key) {
  auto [it, inserted] = by_key_.emplace(key, records_.size());
  if(inserted) records_.push_back(CreditRecord{key, 0, 0});
  return records_[it->second];
}

const CreditRecord* ClientCredits::find(const UserHash& key) const {
  auto it = by_key_.find(key);
  if(it == by_key_.end()) return nullptr;
  return &records_[it->second];
}

} // namespace ed2k::share
