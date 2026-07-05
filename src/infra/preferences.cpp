#include "ed2k/infra/preferences.hpp"

#include <algorithm>
#include <fstream>
#include <span>
#include <string_view>

#include "ed2k/codec/byte_io.hpp"
#include "ed2k/codec/tag.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::infra {
namespace {
constexpr std::uint32_t preferences_magic = 0x46503245; // E2PF
constexpr std::uint16_t preferences_version = 1;

std::vector<std::byte> read_all(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  in.seekg(0, std::ios::end);
  const auto size = in.tellg();
  in.seekg(0, std::ios::beg);
  if (size <= 0) {
    return {};
  }
  std::vector<std::byte> out(static_cast<std::size_t>(size));
  in.read(reinterpret_cast<char*>(out.data()), size);
  if (!in) {
    return {};
  }
  return out;
}

codec::Tag uint_tag(std::string name, std::uint64_t value) {
  codec::Tag tag;
  tag.name_str = std::move(name);
  tag.value = value;
  return tag;
}

codec::Tag string_tag(std::string name, std::string value) {
  codec::Tag tag;
  tag.name_str = std::move(name);
  tag.value = std::move(value);
  return tag;
}

codec::Tag blob_tag(std::string name, std::vector<std::byte> value) {
  codec::Tag tag;
  tag.name_str = std::move(name);
  tag.value = std::move(value);
  return tag;
}

std::string path_string(const std::filesystem::path& path) {
  return path.generic_string();
}

std::string join_paths(const std::vector<std::filesystem::path>& paths) {
  std::string out;
  for (std::size_t i = 0; i < paths.size(); ++i) {
    if (i != 0) {
      out.push_back('\n');
    }
    out += paths[i].generic_string();
  }
  return out;
}

std::vector<std::filesystem::path> split_paths(std::string_view text) {
  std::vector<std::filesystem::path> out;
  while (!text.empty()) {
    const auto pos = text.find('\n');
    const auto item = pos == std::string_view::npos ? text : text.substr(0, pos);
    if (!item.empty()) {
      out.emplace_back(std::string(item));
    }
    if (pos == std::string_view::npos) {
      break;
    }
    text.remove_prefix(pos + 1);
  }
  return out;
}

std::uint64_t as_u64(const codec::Tag& tag, std::uint64_t fallback) {
  if (auto value = std::get_if<std::uint64_t>(&tag.value)) {
    return *value;
  }
  return fallback;
}

std::string as_string(const codec::Tag& tag, std::string fallback) {
  if (auto value = std::get_if<std::string>(&tag.value)) {
    return *value;
  }
  return fallback;
}

bool as_bool(const codec::Tag& tag, bool fallback) {
  return as_u64(tag, fallback ? 1u : 0u) != 0;
}

const std::vector<std::byte>* as_blob(const codec::Tag& tag) {
  return std::get_if<std::vector<std::byte>>(&tag.value);
}

void apply_tag(Preferences& prefs, const codec::Tag& tag) {
  const auto& name = tag.name_str;
  if (name == "nickname") prefs.nickname = as_string(tag, prefs.nickname);
  else if (name == "tcp_port") prefs.tcp_port = static_cast<std::uint16_t>(as_u64(tag, prefs.tcp_port));
  else if (name == "udp_port") prefs.udp_port = static_cast<std::uint16_t>(as_u64(tag, prefs.udp_port));
  else if (name == "server_udp_port") prefs.server_udp_port = static_cast<std::uint16_t>(as_u64(tag, prefs.server_udp_port));
  else if (name == "upload_limit_bps") prefs.upload_limit_bps = static_cast<std::uint32_t>(as_u64(tag, prefs.upload_limit_bps));
  else if (name == "download_limit_bps") prefs.download_limit_bps = static_cast<std::uint32_t>(as_u64(tag, prefs.download_limit_bps));
  else if (name == "upload_slots") prefs.upload_slots = static_cast<std::uint32_t>(as_u64(tag, prefs.upload_slots));
  else if (name == "max_connections") prefs.max_connections = static_cast<std::uint32_t>(as_u64(tag, prefs.max_connections));
  else if (name == "max_sources_per_file") prefs.max_sources_per_file = static_cast<std::uint32_t>(as_u64(tag, prefs.max_sources_per_file));
  else if (name == "connect_timeout_ms") prefs.connect_timeout_ms = static_cast<std::uint32_t>(as_u64(tag, prefs.connect_timeout_ms));
  else if (name == "request_timeout_ms") prefs.request_timeout_ms = static_cast<std::uint32_t>(as_u64(tag, prefs.request_timeout_ms));
  else if (name == "kad_request_timeout_ms") prefs.kad_request_timeout_ms = static_cast<std::uint32_t>(as_u64(tag, prefs.kad_request_timeout_ms));
  else if (name == "http_update_interval_minutes") prefs.http_update_interval_minutes = static_cast<std::uint32_t>(as_u64(tag, prefs.http_update_interval_minutes));
  else if (name == "ip_filter_level") prefs.ip_filter_level = static_cast<std::uint8_t>(as_u64(tag, prefs.ip_filter_level));
  else if (name == "enable_server") prefs.enable_server = as_bool(tag, prefs.enable_server);
  else if (name == "enable_kad") prefs.enable_kad = as_bool(tag, prefs.enable_kad);
  else if (name == "enable_ip_filter") prefs.enable_ip_filter = as_bool(tag, prefs.enable_ip_filter);
  else if (name == "enable_obfuscation") prefs.enable_obfuscation = as_bool(tag, prefs.enable_obfuscation);
  else if (name == "request_obfuscation") prefs.request_obfuscation = as_bool(tag, prefs.request_obfuscation);
  else if (name == "require_obfuscation") prefs.require_obfuscation = as_bool(tag, prefs.require_obfuscation);
  else if (name == "udp_obfuscation_fallback") prefs.udp_obfuscation_fallback = as_bool(tag, prefs.udp_obfuscation_fallback);
  else if (name == "auto_update_server_met") prefs.auto_update_server_met = as_bool(tag, prefs.auto_update_server_met);
  else if (name == "auto_update_nodes_dat") prefs.auto_update_nodes_dat = as_bool(tag, prefs.auto_update_nodes_dat);
  else if (name == "auto_update_ipfilter") prefs.auto_update_ipfilter = as_bool(tag, prefs.auto_update_ipfilter);
  else if (name == "share_hidden_files") prefs.share_hidden_files = as_bool(tag, prefs.share_hidden_files);
  else if (name == "incoming_dir") prefs.incoming_dir = as_string(tag, path_string(prefs.incoming_dir));
  else if (name == "temp_dir") prefs.temp_dir = as_string(tag, path_string(prefs.temp_dir));
  else if (name == "config_dir") prefs.config_dir = as_string(tag, path_string(prefs.config_dir));
  else if (name == "server_met_path") prefs.server_met_path = as_string(tag, path_string(prefs.server_met_path));
  else if (name == "nodes_dat_path") prefs.nodes_dat_path = as_string(tag, path_string(prefs.nodes_dat_path));
  else if (name == "ipfilter_dat_path") prefs.ipfilter_dat_path = as_string(tag, path_string(prefs.ipfilter_dat_path));
  else if (name == "known_met_path") prefs.known_met_path = as_string(tag, path_string(prefs.known_met_path));
  else if (name == "known2_met_path") prefs.known2_met_path = as_string(tag, path_string(prefs.known2_met_path));
  else if (name == "clients_met_path") prefs.clients_met_path = as_string(tag, path_string(prefs.clients_met_path));
  else if (name == "stat_dat_path") prefs.stat_dat_path = as_string(tag, path_string(prefs.stat_dat_path));
  else if (name == "shared_dirs") prefs.shared_dirs = split_paths(as_string(tag, {}));
  else if (name == "categories") {
    if (const auto* bytes = as_blob(tag)) {
      if (auto categories = parse_categories(*bytes)) {
        prefs.categories = std::move(*categories);
      }
    }
  }
}

std::vector<codec::Tag> tags_for(const Preferences& prefs) {
  return {
      string_tag("nickname", prefs.nickname),
      uint_tag("tcp_port", prefs.tcp_port),
      uint_tag("udp_port", prefs.udp_port),
      uint_tag("server_udp_port", prefs.server_udp_port),
      uint_tag("upload_limit_bps", prefs.upload_limit_bps),
      uint_tag("download_limit_bps", prefs.download_limit_bps),
      uint_tag("upload_slots", prefs.upload_slots),
      uint_tag("max_connections", prefs.max_connections),
      uint_tag("max_sources_per_file", prefs.max_sources_per_file),
      uint_tag("connect_timeout_ms", prefs.connect_timeout_ms),
      uint_tag("request_timeout_ms", prefs.request_timeout_ms),
      uint_tag("kad_request_timeout_ms", prefs.kad_request_timeout_ms),
      uint_tag("http_update_interval_minutes", prefs.http_update_interval_minutes),
      uint_tag("ip_filter_level", prefs.ip_filter_level),
      uint_tag("enable_server", prefs.enable_server ? 1u : 0u),
      uint_tag("enable_kad", prefs.enable_kad ? 1u : 0u),
      uint_tag("enable_ip_filter", prefs.enable_ip_filter ? 1u : 0u),
      uint_tag("enable_obfuscation", prefs.enable_obfuscation ? 1u : 0u),
      uint_tag("request_obfuscation", prefs.request_obfuscation ? 1u : 0u),
      uint_tag("require_obfuscation", prefs.require_obfuscation ? 1u : 0u),
      uint_tag("udp_obfuscation_fallback", prefs.udp_obfuscation_fallback ? 1u : 0u),
      uint_tag("auto_update_server_met", prefs.auto_update_server_met ? 1u : 0u),
      uint_tag("auto_update_nodes_dat", prefs.auto_update_nodes_dat ? 1u : 0u),
      uint_tag("auto_update_ipfilter", prefs.auto_update_ipfilter ? 1u : 0u),
      uint_tag("share_hidden_files", prefs.share_hidden_files ? 1u : 0u),
      string_tag("incoming_dir", path_string(prefs.incoming_dir)),
      string_tag("temp_dir", path_string(prefs.temp_dir)),
      string_tag("config_dir", path_string(prefs.config_dir)),
      string_tag("server_met_path", path_string(prefs.server_met_path)),
      string_tag("nodes_dat_path", path_string(prefs.nodes_dat_path)),
      string_tag("ipfilter_dat_path", path_string(prefs.ipfilter_dat_path)),
      string_tag("known_met_path", path_string(prefs.known_met_path)),
      string_tag("known2_met_path", path_string(prefs.known2_met_path)),
      string_tag("clients_met_path", path_string(prefs.clients_met_path)),
      string_tag("stat_dat_path", path_string(prefs.stat_dat_path)),
      string_tag("shared_dirs", join_paths(prefs.shared_dirs)),
      blob_tag("categories", write_categories(prefs.categories)),
  };
}
} // namespace

Preferences Preferences::defaults() {
  return {};
}

tl::expected<Preferences, std::error_code> Preferences::load(const std::filesystem::path& path) {
  const auto bytes = read_all(path);
  if (bytes.empty()) {
    return tl::unexpected(make_error_code(errc::io_error));
  }
  codec::ByteReader r(bytes);
  const auto magic = r.u32();
  const auto version = r.u16();
  const auto count = r.u32();
  if (!r.ok()) {
    return tl::unexpected(make_error_code(errc::buffer_underflow));
  }
  if (magic != preferences_magic) {
    return tl::unexpected(make_error_code(errc::bad_magic));
  }
  if (version != preferences_version) {
    return tl::unexpected(make_error_code(errc::unsupported_version));
  }

  auto tags = codec::read_taglist(r, count);
  if (!tags) {
    return tl::unexpected(tags.error());
  }
  Preferences prefs = defaults();
  for (const auto& tag : *tags) {
    apply_tag(prefs, tag);
  }
  return prefs;
}

tl::expected<void, std::error_code> Preferences::save(const std::filesystem::path& path) const {
  codec::ByteWriter w;
  const auto tags = tags_for(*this);
  w.u32(preferences_magic);
  w.u16(preferences_version);
  w.u32(static_cast<std::uint32_t>(tags.size()));
  codec::write_taglist(w, std::span<const codec::Tag>(tags.data(), tags.size()));
  const auto bytes = w.take();

  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return tl::unexpected(make_error_code(errc::io_error));
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (!out) {
    return tl::unexpected(make_error_code(errc::io_error));
  }
  return {};
}

} // namespace ed2k::infra
