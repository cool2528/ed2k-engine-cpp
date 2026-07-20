#pragma once
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/metfile/known_part_met.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::share {

struct KnownFile {
  FileHash hash;
  AICHHash aich_root;
  std::vector<PartHash> part_hashes;
  std::filesystem::path path;
  std::string name;
  std::uint64_t size = 0;
  std::uint32_t date = 0;
  std::uint8_t rating = 0;
  std::string comment;
  std::vector<ed2k::peer::PeerSource> sources;
  auto operator<=>(const KnownFile&) const = default;
};

struct Known2Entry {
  FileHash hash;
  AICHHash aich_root;
  std::vector<AICHHash> part_leaves;
  auto operator<=>(const Known2Entry&) const = default;
};

std::vector<std::byte> write_known_files(std::span<const KnownFile> files);
tl::expected<std::vector<KnownFile>, std::error_code> parse_known_files(std::span<const std::byte> data);

std::vector<std::byte> write_known2_met(std::span<const Known2Entry> entries);
tl::expected<std::vector<Known2Entry>, std::error_code> parse_known2_met(std::span<const std::byte> data);

class KnownFileDB {
 public:
  tl::expected<void, std::error_code> scan_dir(const std::filesystem::path& dir);
  void add(KnownFile file);
  bool add_source(const FileHash& hash, ed2k::peer::PeerSource source);
  bool set_file_desc(const FileHash& hash, std::uint8_t rating, std::string comment);
  const KnownFile* find(const FileHash& hash) const;
  const std::vector<KnownFile>& files() const noexcept { return files_; }

  // 记录一次对该文件的上传请求(STARTUPLOADREQ 命中)
  void note_request(const FileHash& hash) { ++request_counts_[hash]; }
  // 会话内该文件累计被请求次数
  std::uint32_t request_count(const FileHash& hash) const {
    auto it = request_counts_.find(hash);
    return it == request_counts_.end() ? 0u : it->second;
  }
  // 目录重扫整体重建 DB 时迁移旧计数(按 hash)
  void adopt_request_counts(const KnownFileDB& old) { request_counts_ = old.request_counts_; }

 private:
  std::vector<KnownFile> files_;
  std::unordered_map<FileHash, std::size_t> by_hash_;
  std::unordered_map<FileHash, std::uint32_t> request_counts_;
};

} // namespace ed2k::share
