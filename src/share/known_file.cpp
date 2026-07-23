#include "ed2k/share/known_file.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"
#include <algorithm>
#include <chrono>
#include <variant>

namespace ed2k::share {
namespace {
constexpr std::uint8_t KNOWN2_MAGIC = 0x0E;

namespace filetag {
constexpr std::uint8_t Filename = 0x01;
constexpr std::uint8_t Filesize = 0x02;
constexpr std::uint8_t AichFileHash = 0x11;
}

codec::Tag string_tag(std::uint8_t id, std::string v) {
  codec::Tag t;
  t.name_id = id;
  t.value = std::move(v);
  return t;
}

codec::Tag u64_tag(std::uint8_t id, std::uint64_t v) {
  codec::Tag t;
  t.name_id = id;
  t.value = v;
  return t;
}

KnownFileEntry to_known_entry(const KnownFile& f) {
  KnownFileEntry e;
  e.date = f.date;
  e.hash = f.hash;
  e.part_hashes = f.part_hashes;
  e.size = f.size;
  e.tags.push_back(string_tag(filetag::Filename, f.name));
  e.tags.push_back(u64_tag(filetag::Filesize, f.size));
  e.tags.push_back(string_tag(filetag::AichFileHash, f.aich_root.to_base32()));
  return e;
}

KnownFile from_known_entry(KnownFileEntry e) {
  KnownFile f;
  f.date = e.date;
  f.hash = e.hash;
  f.part_hashes = std::move(e.part_hashes);
  f.size = e.size;
  for(const auto& t : e.tags) {
    if(t.name_id == filetag::Filename && std::holds_alternative<std::string>(t.value)) {
      f.name = std::get<std::string>(t.value);
    } else if(t.name_id == filetag::Filesize && std::holds_alternative<std::uint64_t>(t.value)) {
      f.size = std::get<std::uint64_t>(t.value);
    } else if(t.name_id == filetag::AichFileHash && std::holds_alternative<std::string>(t.value)) {
      if(auto a = AICHHash::from_base32(std::get<std::string>(t.value))) f.aich_root = *a;
    }
  }
  return f;
}

// 文件 mtime -> unix 秒: known.met 的 date 字段, 也是缓存复用键 (name,size,date) 的一部分
// (eMule 惯例, 秒级精度)。转换失败(文件不存在/无权限等)时返回 0, 不当作致命错误。
std::uint32_t mtime_unix_seconds(const std::filesystem::path& p) {
  std::error_code ec;
  const auto ftime = std::filesystem::last_write_time(p, ec);
  if(ec) return 0;
  // 不用 std::chrono::clock_cast:libc++ 未实现该 C++20 特性(macOS 部署目标下编译失败)。
  // 以 file_clock 与 system_clock 的当前时刻差值换算,秒级精度下偏差可忽略。
  const auto sys = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
      ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
  return static_cast<std::uint32_t>(
      std::chrono::duration_cast<std::chrono::seconds>(sys.time_since_epoch()).count());
}

tl::expected<KnownFile, std::error_code> known_from_path(const std::filesystem::path& p) {
  std::error_code ec;
  auto size = std::filesystem::file_size(p, ec);
  if(ec) return tl::unexpected(make_error_code(errc::io_error));
  auto h = hash_file(p, HashVariant::Red);
  if(!h) return tl::unexpected(h.error());
  auto a = aich_hash_file(p);
  if(!a) return tl::unexpected(a.error());
  KnownFile f;
  f.hash = h->file_hash;
  f.part_hashes = std::move(h->part_hashes);
  f.aich_root = *a;
  f.path = p;
  f.name = p.filename().string();
  f.size = size;
  f.date = mtime_unix_seconds(p);
  return f;
}
} // namespace

std::vector<std::byte> write_known_files(std::span<const KnownFile> files) {
  std::vector<KnownFileEntry> entries;
  entries.reserve(files.size());
  for(const auto& f : files) entries.push_back(to_known_entry(f));
  return write_known_met(entries);
}

tl::expected<std::vector<KnownFile>, std::error_code> parse_known_files(std::span<const std::byte> data) {
  auto entries = parse_known_met(data);
  if(!entries) return tl::unexpected(entries.error());
  std::vector<KnownFile> out;
  out.reserve(entries->size());
  for(auto& e : *entries) out.push_back(from_known_entry(std::move(e)));
  return out;
}

std::vector<std::byte> write_known2_met(std::span<const Known2Entry> entries) {
  codec::ByteWriter w;
  w.u8(KNOWN2_MAGIC);
  w.u32(static_cast<std::uint32_t>(entries.size()));
  for(const auto& e : entries) {
    w.hash16(e.hash);
    w.hash20(e.aich_root.bytes());
    w.u16(static_cast<std::uint16_t>(e.part_leaves.size()));
    for(const auto& leaf : e.part_leaves) w.hash20(leaf.bytes());
  }
  return w.take();
}

tl::expected<std::vector<Known2Entry>, std::error_code> parse_known2_met(std::span<const std::byte> data) {
  codec::ByteReader r(data);
  const auto magic = r.u8();
  if(magic != KNOWN2_MAGIC) return tl::unexpected(make_error_code(errc::bad_magic));
  const auto count = r.u32();
  if(count > 1000000) return tl::unexpected(make_error_code(errc::count_too_large));
  std::vector<Known2Entry> out;
  out.reserve(count);
  for(std::uint32_t i = 0; i < count; ++i) {
    Known2Entry e;
    e.hash = r.hash16();
    e.aich_root = AICHHash::from_bytes(r.hash20());
    const auto leaves = r.u16();
    e.part_leaves.reserve(leaves);
    for(std::uint16_t k = 0; k < leaves; ++k) e.part_leaves.push_back(AICHHash::from_bytes(r.hash20()));
    if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
    out.push_back(std::move(e));
  }
  return out;
}

tl::expected<void, std::error_code> KnownFileDB::scan_dir(const std::filesystem::path& dir, const KnownFileDB* cache) {
  std::error_code ec;
  if(!std::filesystem::exists(dir, ec) || ec) return tl::unexpected(make_error_code(errc::io_error));
  for(std::filesystem::directory_iterator it(dir, ec), end; it != end; it.increment(ec)) {
    if(ec) return tl::unexpected(make_error_code(errc::io_error));
    if(!it->is_regular_file(ec) || ec) {
      if(ec) return tl::unexpected(make_error_code(errc::io_error));
      continue;
    }
    // 缓存 (name,size,date) 命中 -> 跳过重哈希, 直接复用旧条目(仅刷新 path)
    if(cache != nullptr) {
      // 复用键: 文件名+大小+mtime(eMule known.met 惯例, met 格式本身不含路径)
      const auto name = it->path().filename().string();
      std::error_code fec;
      const auto fsize = std::filesystem::file_size(it->path(), fec);
      const auto fdate = mtime_unix_seconds(it->path());
      // fdate==0 表示当前文件 mtime 读取失败(权限/文件系统异常等), 此时禁止走缓存探测:
      // 若缓存中恰好也存在 date==0 的旧条目(例如缓存产生时同样遭遇 mtime 失败), 二者会仅凭
      // name+size 误判命中, 复用一个可能早已过期的哈希——直接跳过探测、落入真实哈希分支更安全。
      if(!fec && fdate != 0) {
        const KnownFile* hit = nullptr;
        for(const auto& c : cache->files())
          if(c.name == name && c.size == fsize && c.date == fdate) { hit = &c; break; }
        if(hit != nullptr) {
          KnownFile reused = *hit;
          reused.path = it->path();
          add(std::move(reused));
          continue;
        }
      }
    }
    auto f = known_from_path(it->path());
    if(!f) return tl::unexpected(f.error());
    add(std::move(*f));
  }
  return {};
}

void KnownFileDB::add(KnownFile file) {
  auto [it, inserted] = by_hash_.emplace(file.hash, files_.size());
  if(inserted) {
    files_.push_back(std::move(file));
  } else {
    files_[it->second] = std::move(file);
  }
}

bool KnownFileDB::add_source(const FileHash& hash, ed2k::peer::PeerSource source) {
  auto it = by_hash_.find(hash);
  if(it == by_hash_.end()) return false;
  auto& sources = files_[it->second].sources;
  auto existing = std::find_if(sources.begin(), sources.end(), [&](const ed2k::peer::PeerSource& current) {
    return current.user_hash == source.user_hash;
  });
  if(existing == sources.end()) {
    sources.push_back(std::move(source));
  } else {
    *existing = std::move(source);
  }
  return true;
}

bool KnownFileDB::set_file_desc(const FileHash& hash, std::uint8_t rating, std::string comment) {
  auto it = by_hash_.find(hash);
  if(it == by_hash_.end()) return false;
  files_[it->second].rating = rating;
  files_[it->second].comment = std::move(comment);
  return true;
}

const KnownFile* KnownFileDB::find(const FileHash& hash) const {
  auto it = by_hash_.find(hash);
  if(it == by_hash_.end()) return nullptr;
  return &files_[it->second];
}

} // namespace ed2k::share
