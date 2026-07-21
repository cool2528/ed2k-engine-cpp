#include <cstdio>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <fstream>
#include <chrono>
#include <optional>
#include <cstddef>
#include <memory>
#include "ed2k/version.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "ed2k/metfile/server_met.hpp"
#include "ed2k/app/server_session.hpp"
#include "ed2k/infra/collection.hpp"
#include "ed2k/infra/http_download.hpp"
#include "ed2k/infra/ip_filter.hpp"
#include "ed2k/infra/preferences.hpp"
#include "ed2k/infra/proxy.hpp"
#include "ed2k/infra/scheduler.hpp"
#include "ed2k/infra/statistics.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/server/connection.hpp"
#include "ed2k/server/search_query.hpp"
#include "ed2k/share/known_file.hpp"
#include "ed2k/kad/keywords.hpp"
#include "ed2k/kad/messages.hpp"
#include "ed2k/kad/network.hpp"
#include "ed2k/kad/nodes_dat.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
namespace asio = boost::asio;
using namespace ed2k;
static constexpr std::size_t k_kad_bootstrap_seed_limit = 256;
static constexpr std::chrono::milliseconds k_kad_bootstrap_timeout{1500};
static constexpr std::chrono::milliseconds k_kad_request_timeout{60000};
static int usage(){ std::puts("usage: ed2k-tool hash <file> [--aich] [--red]\n"
  "       ed2k-tool [--config <preferences.dat>] [--ipfilter <ipfilter.dat>] [--proxy <uri>] [--obfuscation] <command> ...\n"
  "       ed2k-tool serverlist <server.met>\n"
  "       ed2k-tool parse <ed2k-link>\n"
  "       ed2k-tool login <server.met> [--ip:x.x.x.x] [--port:n]\n"
  "       ed2k-tool get-serverlist <server.met>\n"
  "       ed2k-tool search <server.met> <keyword>\n"
  "       ed2k-tool sources <server.met> <ed2k-link>\n"
  "       ed2k-tool publish <dir> [--server:server.met] [--ip:x.x.x.x] [--port:n]\n"
  "       ed2k-tool comment <ed2k-link> --rating:n --comment:text [--peer:ip:port] [--peer-hash:32hex]\n"
  "       ed2k-tool ipfilter <ipfilter.dat> [--block-check:ip] [--level:n]\n"
  "       ed2k-tool config <preferences.dat> [--set:key=value]\n"
  "       ed2k-tool stats <statistics.dat>\n"
  "       ed2k-tool collection list <collection> | collection create <collection> <ed2k-link>...\n"
  "       ed2k-tool schedule list <rules.txt> | schedule add <rules.txt> <rule>\n"
  "       ed2k-tool update-serverlist <url> <dest>\n"
  "       ed2k-tool kad-bootstrap <nodes.dat>\n"
  "       ed2k-tool kad-search <nodes.dat> <keyword>\n"
  "       ed2k-tool kad-find-sources <nodes.dat> <ed2k-link>\n"
  "       ed2k-tool kad-publish <nodes.dat> <dir> [--port:n]\n"
  "       ed2k-tool download <ed2k-link> [--out:PATH] [--server:server.met]"); return 2; }
static std::vector<std::byte> read_all(const char* p){
  std::ifstream f(p,std::ios::binary); std::vector<std::byte> v;
  f.seekg(0,std::ios::end); auto n=f.tellg(); f.seekg(0);
  if(n>0){ v.resize(std::size_t(n)); f.read(reinterpret_cast<char*>(v.data()),n); } return v;
}
static bool write_all_bytes(const std::filesystem::path& path, std::span<const std::byte> bytes){
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if(!f) return false;
  f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(f);
}
static std::string read_text_file(const std::filesystem::path& path){
  std::ifstream f(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
static bool write_text_file(const std::filesystem::path& path, std::string_view text, bool append = false){
  std::ofstream f(path, std::ios::binary | (append ? std::ios::app : std::ios::trunc));
  if(!f) return false;
  f.write(text.data(), static_cast<std::streamsize>(text.size()));
  return static_cast<bool>(f);
}
static std::string hex_bytes(std::span<const std::byte> data){
  static constexpr char d[] = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for(auto b : data){
    auto v = std::to_integer<unsigned>(b);
    out.push_back(d[(v >> 4) & 0x0f]);
    out.push_back(d[v & 0x0f]);
  }
  return out;
}
static std::optional<std::pair<IPv4, std::uint16_t>> parse_peer(std::string_view s){
  auto colon = s.rfind(':');
  if(colon == std::string_view::npos) return std::nullopt;
  auto ip = IPv4::from_dotted(s.substr(0, colon));
  if(!ip) return std::nullopt;
  return std::pair{*ip, static_cast<std::uint16_t>(std::stoi(std::string(s.substr(colon + 1))))};
}
static ed2k::peer::HelloInfo cli_hello(
    ed2k::peer::ObfuscationPolicy policy = ed2k::peer::ObfuscationPolicy::disabled){
  ed2k::peer::HelloInfo h;
  h.nickname = "ed2k-tool";
  h.version = 0x3C;
  h.port = 4662;
  h.user_hash = *UserHash::from_hex("0123456789abcdeffedcba9876543210");
  h.supports_obfuscation = policy != ed2k::peer::ObfuscationPolicy::disabled;
  h.requests_obfuscation = policy != ed2k::peer::ObfuscationPolicy::disabled;
  h.requires_obfuscation = policy == ed2k::peer::ObfuscationPolicy::required;
  return h;
}
static ed2k::UserHash cli_user_hash(){
  return *UserHash::from_hex("0123456789abcdeffedcba9876543210");
}
static ed2k::kad::KadID kad_id_from_hash(const ed2k::FileHash& hash){
  return ed2k::kad::KadID::from_bytes(hash.bytes());
}
static ed2k::kad::KadID cli_kad_user_hash(){
  auto hash = cli_user_hash();
  return ed2k::kad::KadID::from_bytes(hash.bytes());
}
static ed2k::server::LoginParams cli_login_params(const ed2k::infra::Preferences& prefs){
  ed2k::server::LoginParams p;
  p.nickname = prefs.nickname;
  p.client_port = prefs.tcp_port;
  p.user_hash = cli_user_hash();
  return p;
}
static ed2k::peer::ObfuscationPolicy cli_obfuscation_policy(const ed2k::infra::Preferences& prefs) {
  if(prefs.require_obfuscation) return ed2k::peer::ObfuscationPolicy::required;
  if(prefs.enable_obfuscation && prefs.request_obfuscation)
    return ed2k::peer::ObfuscationPolicy::preferred;
  return ed2k::peer::ObfuscationPolicy::disabled;
}
static ed2k::kad::KadNetworkOptions cli_kad_options(
    std::uint16_t tcp_port,
    std::shared_ptr<const ed2k::infra::IPFilter> ip_filter = nullptr,
    std::uint8_t ip_filter_level = 127){
  auto user_hash = cli_user_hash();
  return ed2k::kad::KadNetworkOptions{
    .id = ed2k::kad::KadID::from_user_hash(user_hash, 1),
    .ip = ed2k::IPv4::from_dotted("0.0.0.0").value(),
    .tcp_port = tcp_port,
    .version = ed2k::kad::kad2_version,
    .user_hash = ed2k::kad::KadID::from_bytes(user_hash.bytes()),
    .ip_filter = std::move(ip_filter),
    .ip_filter_level = ip_filter_level,
  };
}
static codec::Tag kad_int_tag(std::uint8_t name_id, std::uint64_t value){
  codec::Tag tag;
  tag.name_str = std::string(1, static_cast<char>(name_id));
  tag.value = value;
  return tag;
}
static codec::Tag kad_string_tag(std::uint8_t name_id, std::string value){
  codec::Tag tag;
  tag.name_str = std::string(1, static_cast<char>(name_id));
  tag.value = std::move(value);
  return tag;
}
static ed2k::kad::KadSearchEntry kad_file_entry(const ed2k::share::KnownFile& file){
  return ed2k::kad::KadSearchEntry{
    .answer_id = kad_id_from_hash(file.hash),
    .tags = {
      kad_string_tag(ed2k::kad::tag::filename, file.name),
      kad_int_tag(ed2k::kad::tag::file_size, file.size),
    },
  };
}
static ed2k::kad::KadSearchEntry kad_source_entry(const ed2k::share::KnownFile& file,
                                                  std::uint16_t tcp_port,
                                                  std::uint16_t udp_port){
  return ed2k::kad::KadSearchEntry{
    .answer_id = cli_kad_user_hash(),
    .tags = {
      kad_int_tag(ed2k::kad::tag::source_type, 1),
      kad_int_tag(ed2k::kad::tag::source_port, tcp_port),
      kad_int_tag(ed2k::kad::tag::source_udp_port, udp_port),
      kad_int_tag(ed2k::kad::tag::file_size, file.size),
    },
  };
}
static bool parse_bool_arg(std::string_view value){
  return value == "1" || value == "true" || value == "yes" || value == "on";
}
static bool apply_preference_set(ed2k::infra::Preferences& prefs, std::string_view assignment){
  auto eq = assignment.find('=');
  if(eq == std::string_view::npos) return false;
  auto key = assignment.substr(0, eq);
  auto value = assignment.substr(eq + 1);
  auto number = [&] { return static_cast<std::uint32_t>(std::stoul(std::string(value))); };
  if(key == "nickname") prefs.nickname = std::string(value);
  else if(key == "tcp_port") prefs.tcp_port = static_cast<std::uint16_t>(number());
  else if(key == "udp_port") prefs.udp_port = static_cast<std::uint16_t>(number());
  else if(key == "server_udp_port") prefs.server_udp_port = static_cast<std::uint16_t>(number());
  else if(key == "upload_limit_bps") prefs.upload_limit_bps = number();
  else if(key == "download_limit_bps") prefs.download_limit_bps = number();
  else if(key == "upload_slots") prefs.upload_slots = number();
  else if(key == "max_connections") prefs.max_connections = number();
  else if(key == "max_sources_per_file") prefs.max_sources_per_file = number();
  else if(key == "ip_filter_level") prefs.ip_filter_level = static_cast<std::uint8_t>(number());
  else if(key == "incoming_dir") prefs.incoming_dir = std::string(value);
  else if(key == "temp_dir") prefs.temp_dir = std::string(value);
  else if(key == "server_met_path") prefs.server_met_path = std::string(value);
  else if(key == "nodes_dat_path") prefs.nodes_dat_path = std::string(value);
  else if(key == "ipfilter_dat_path") prefs.ipfilter_dat_path = std::string(value);
  else if(key == "enable_kad") prefs.enable_kad = parse_bool_arg(value);
  else if(key == "enable_ip_filter") prefs.enable_ip_filter = parse_bool_arg(value);
  else if(key == "enable_obfuscation") prefs.enable_obfuscation = parse_bool_arg(value);
  else if(key == "request_obfuscation") prefs.request_obfuscation = parse_bool_arg(value);
  else if(key == "require_obfuscation") prefs.require_obfuscation = parse_bool_arg(value);
  else return false;
  return true;
}
struct CliGlobals {
  std::optional<std::filesystem::path> config_path;
  std::optional<std::filesystem::path> ipfilter_path;
  std::optional<ed2k::infra::ProxyConfig> proxy;
  bool obfuscation = false;
  bool valid = true;
  std::vector<std::string> args;
};
static CliGlobals parse_cli_globals(int argc, char** argv){
  CliGlobals out;
  for(int i=1;i<argc;++i){
    std::string a=argv[i];
    if(a=="--config"){
      if(i+1>=argc){ out.valid=false; return out; }
      out.config_path = argv[++i];
    } else if(a.rfind("--config:",0)==0) {
      out.config_path = a.substr(9);
    } else if(a=="--ipfilter"){
      if(i+1>=argc){ out.valid=false; return out; }
      out.ipfilter_path = argv[++i];
    } else if(a.rfind("--ipfilter:",0)==0) {
      out.ipfilter_path = a.substr(11);
    } else if(a=="--proxy"){
      if(i+1>=argc){ out.valid=false; return out; }
      auto parsed = ed2k::infra::ProxyConfig::parse(argv[++i]);
      if(!parsed){ out.valid=false; return out; }
      out.proxy = *parsed;
    } else if(a.rfind("--proxy:",0)==0) {
      auto parsed = ed2k::infra::ProxyConfig::parse(a.substr(8));
      if(!parsed){ out.valid=false; return out; }
      out.proxy = *parsed;
    } else if(a=="--obfuscation") {
      out.obfuscation = true;
    } else {
      out.args.push_back(std::move(a));
    }
  }
  return out;
}
static bool looks_like_option(std::string_view text){
  return text.rfind("--", 0) == 0;
}
static std::string join_args(char** argv, int first, int argc){
  std::string out;
  for(int i=first;i<argc;++i){
    if(i != first) out.push_back(' ');
    out += argv[i];
  }
  return out;
}
static tl::expected<ed2k::infra::Preferences, std::error_code>
load_cli_preferences(const CliGlobals& globals){
  auto prefs = ed2k::infra::Preferences::defaults();
  if(globals.config_path && std::filesystem::exists(*globals.config_path)){
    auto loaded = ed2k::infra::Preferences::load(*globals.config_path);
    if(!loaded) return tl::unexpected(loaded.error());
    prefs = std::move(*loaded);
  }
  if(globals.obfuscation){
    prefs.enable_obfuscation = true;
    prefs.request_obfuscation = true;
  }
  return prefs;
}
static tl::expected<std::shared_ptr<const ed2k::infra::IPFilter>, std::error_code>
load_cli_ip_filter(const CliGlobals& globals, const ed2k::infra::Preferences& prefs){
  std::optional<std::filesystem::path> path = globals.ipfilter_path;
  if(!path && prefs.enable_ip_filter && !prefs.ipfilter_dat_path.empty() &&
     std::filesystem::exists(prefs.ipfilter_dat_path)){
    path = prefs.ipfilter_dat_path;
  }
  if(!path) return std::shared_ptr<const ed2k::infra::IPFilter>{};
  auto filter = ed2k::infra::IPFilter::load(*path);
  if(!filter) return tl::unexpected(filter.error());
  return std::make_shared<ed2k::infra::IPFilter>(std::move(*filter));
}
static tl::expected<std::vector<ed2k::kad::Contact>, std::error_code>
load_kad_nodes(const char* path){
  return ed2k::kad::parse_nodes_dat(read_all(path));
}
static asio::awaitable<tl::expected<void, std::error_code>>
bootstrap_if_needed(ed2k::kad::KadNetwork& network,
                    const std::vector<ed2k::kad::Contact>& contacts,
                    std::chrono::milliseconds timeout){
  if(contacts.empty()) co_return tl::expected<void, std::error_code>{};
  const auto seed_count = std::min(contacts.size(), k_kad_bootstrap_seed_limit);
  co_return co_await network.bootstrap(std::span<const ed2k::kad::Contact>(contacts.data(), seed_count), timeout);
}
int main(int argc,char** argv){
  auto globals = parse_cli_globals(argc, argv);
  if(!globals.valid) return usage();
  std::vector<std::string> arg_storage = std::move(globals.args);
  std::vector<char*> arg_ptrs;
  arg_ptrs.push_back(argv[0]);
  for(auto& arg : arg_storage) arg_ptrs.push_back(arg.data());
  argc = static_cast<int>(arg_ptrs.size());
  argv = arg_ptrs.data();
  if(argc<2) return usage();
  std::string cmd=argv[1];
  auto startup_prefs = load_cli_preferences(globals);
  if(!startup_prefs){ std::printf("error: %s\n", startup_prefs.error().message().c_str()); return 1; }
  if(cmd=="hash"){
    if(argc<3) return usage();
    bool red=false, aich=false;
    for(int i=3;i<argc;++i){ std::string a=argv[i]; if(a=="--red")red=true; else if(a=="--aich")aich=true; }
    auto r=hash_file(argv[2], red?HashVariant::Red:HashVariant::Blue);
    if(!r){ std::printf("error: %s\n", r.error().message().c_str()); return 1; }
    Ed2kFileLink link; link.name=argv[2];
    { std::error_code ec; link.size=std::filesystem::file_size(argv[2],ec); }
    link.hash=r->file_hash;
    if(aich){ auto a=aich_hash_file(argv[2]); if(a) link.aich=*a; }
    std::printf("%s\n", to_string(link).c_str());
    return 0;
  }
  if(cmd=="serverlist"){
    if(argc<3) return usage();
    auto bytes=read_all(argv[2]);
    auto list=parse_server_met(bytes);
    if(!list){ std::printf("error: %s\n", list.error().message().c_str()); return 1; }
    std::printf("%-22s %-6s %-8s %s\n","IP","PORT","MAXUSER","NAME");
    for(auto& s:list->servers)
      std::printf("%-22s %-6u %-8u %s\n",(s.ip.to_dotted()).c_str(),s.port,s.max_users,s.name.c_str());
    std::printf("(%zu servers)\n", list->servers.size());
    return 0;
  }
  if(cmd=="get-serverlist"){
    if(argc<3) return usage();
    const std::filesystem::path met_path = argv[2];
    auto metbytes = read_all(argv[2]);
    auto existing = parse_server_met(metbytes);
    if(!existing){ std::printf("error: %s\n", existing.error().message().c_str()); return 1; }
    auto global_filter = load_cli_ip_filter(globals, *startup_prefs);
    if(!global_filter){ std::printf("error: %s\n", global_filter.error().message().c_str()); return 1; }
    ed2k::net::IoRuntime rt;
    auto p = cli_login_params(*startup_prefs);
    std::optional<std::vector<std::pair<IPv4, std::uint16_t>>> fetched;
    int rc = 0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      auto login = co_await ed2k::app::login_with_rotation(
        rt.executor(), metbytes, std::nullopt, p,
        std::chrono::milliseconds(startup_prefs->connect_timeout_ms),
        globals.proxy, *global_filter, startup_prefs->ip_filter_level);
      if(!login){
        std::printf("error: %s\n", login.error().message().c_str());
        rc = 1;
        rt.stop();
        co_return;
      }
      auto list = co_await login->conn.get_server_list(std::chrono::milliseconds(startup_prefs->connect_timeout_ms));
      login->conn.close();
      if(!list){
        std::printf("error: %s\n", list.error().message().c_str());
        rc = 1;
      } else {
        fetched = std::move(*list);
      }
      rt.stop();
      co_return;
    }, asio::detached);
    rt.run();
    if(rc != 0 || !fetched) return 1;
    auto merged = merge_server_list(std::move(*existing), std::span<const std::pair<IPv4, std::uint16_t>>(*fetched));
    auto out = write_server_met(merged);
    if(!write_all_bytes(met_path, out)){ std::printf("error: io error\n"); return 1; }
    std::printf("updated %s (%zu servers)\n", met_path.string().c_str(), merged.servers.size());
    return 0;
  }
  if(cmd=="parse"){
    if(argc<3) return usage();
    auto r=parse_link(argv[2]);
    if(!r){ std::printf("error: %s\n", r.error().message().c_str()); return 1; }
    if(auto* f=std::get_if<Ed2kFileLink>(&*r))
      std::printf("file: name=%s size=%llu hash=%s aich=%s sources=%zu\n",
        f->name.c_str(),(unsigned long long)f->size,f->hash.to_hex().c_str(),
        f->aich?f->aich->to_base32().c_str():"-", f->sources.size());
    else if(auto* s=std::get_if<ServerLink>(&*r))
      std::printf("server: %s:%u\n", s->ip.to_dotted().c_str(), s->port);
    else if(auto* sl=std::get_if<ServerListLink>(&*r))
      std::printf("serverlist: %s\n", sl->url.c_str());
    return 0;
  }
  if(cmd=="ipfilter"){
    if(argc<3 && !globals.ipfilter_path) return usage();
    std::filesystem::path path;
    int option_start = 3;
    if(globals.ipfilter_path && (argc<3 || looks_like_option(argv[2]))){
      path = *globals.ipfilter_path;
      option_start = 2;
    } else {
      path = argv[2];
    }
    auto filter = ed2k::infra::IPFilter::load(path);
    if(!filter){ std::printf("error: %s\n", filter.error().message().c_str()); return 1; }
    std::optional<IPv4> check_ip;
    std::uint8_t level = 127;
    for(int i=option_start;i<argc;++i){
      std::string a=argv[i];
      if(a.rfind("--block-check:",0)==0){
        auto ip = IPv4::from_dotted(a.substr(14));
        if(!ip){ std::printf("error: invalid block-check ip\n"); return 1; }
        check_ip = *ip;
      } else if(a.rfind("--level:",0)==0){
        auto v = std::stoul(a.substr(8));
        if(v > 255){ std::printf("error: level must be 0..255\n"); return 1; }
        level = static_cast<std::uint8_t>(v);
      }
    }
    if(check_ip){
      std::printf("%s: %s\n", check_ip->to_dotted().c_str(),
                  filter->blocked(*check_ip, level) ? "blocked" : "allowed");
    } else {
      std::printf("ipfilter ranges: %zu\n", filter->ranges().size());
    }
    return 0;
  }
  if(cmd=="config"){
    if(argc<3 && !globals.config_path) return usage();
    std::filesystem::path path;
    int option_start = 3;
    if(globals.config_path && (argc<3 || looks_like_option(argv[2]))){
      path = *globals.config_path;
      option_start = 2;
    } else {
      path = argv[2];
    }
    ed2k::infra::Preferences prefs = ed2k::infra::Preferences::defaults();
    if(std::filesystem::exists(path)){
      auto loaded = ed2k::infra::Preferences::load(path);
      if(!loaded){ std::printf("error: %s\n", loaded.error().message().c_str()); return 1; }
      prefs = std::move(*loaded);
    }
    bool changed = false;
    for(int i=option_start;i<argc;++i){
      std::string a=argv[i];
      if(a.rfind("--set:",0)==0){
        if(!apply_preference_set(prefs, a.substr(6))){
          std::printf("error: invalid preference assignment\n");
          return 1;
        }
        changed = true;
      }
    }
    if(changed){
      auto saved = prefs.save(path);
      if(!saved){ std::printf("error: %s\n", saved.error().message().c_str()); return 1; }
    }
    std::printf("nickname=%s tcp=%u udp=%u kad=%d ipfilter_level=%u\n",
                prefs.nickname.c_str(), prefs.tcp_port, prefs.udp_port,
                prefs.enable_kad ? 1 : 0, prefs.ip_filter_level);
    return 0;
  }
  if(cmd=="collection"){
    if(argc<4) return usage();
    std::string sub = argv[2];
    const std::filesystem::path path = argv[3];
    if(sub=="create"){
      if(argc<5) return usage();
      ed2k::infra::Collection collection;
      for(int i=4;i<argc;++i){
        auto parsed = parse_link(argv[i]);
        if(!parsed){ std::printf("error: %s\n", parsed.error().message().c_str()); return 1; }
        auto* file = std::get_if<Ed2kFileLink>(&*parsed);
        if(!file){ std::printf("error: not a file link\n"); return 1; }
        collection.files.push_back(*file);
      }
      if(!write_text_file(path, ed2k::infra::write_collection_text(collection))){
        std::printf("error: io error\n");
        return 1;
      }
      std::printf("collection files=%zu\n", collection.files.size());
      return 0;
    }
    if(sub=="list"){
      auto text = read_text_file(path);
      auto collection = ed2k::infra::parse_collection_text(text);
      if(!collection){
        auto bytes = read_all(path.string().c_str());
        collection = ed2k::infra::parse_collection_binary(bytes);
      }
      if(!collection){ std::printf("error: %s\n", collection.error().message().c_str()); return 1; }
      for(const auto& file : collection->files) std::printf("%s\n", to_string(file).c_str());
      std::printf("(%zu files)\n", collection->files.size());
      return 0;
    }
    return usage();
  }
  if(cmd=="schedule"){
    if(argc<4) return usage();
    std::string sub = argv[2];
    const std::filesystem::path path = argv[3];
    if(sub=="add"){
      if(argc<5) return usage();
      auto rule = join_args(argv, 4, argc);
      auto parsed = ed2k::infra::SchedulerRule::parse(rule);
      if(!parsed){ std::printf("error: %s\n", parsed.error().message().c_str()); return 1; }
      if(!write_text_file(path, rule + "\n", true)){
        std::printf("error: io error\n");
        return 1;
      }
      std::printf("schedule added\n");
      return 0;
    }
    if(sub=="list"){
      auto text = read_text_file(path);
      std::printf("%s", text.c_str());
      return 0;
    }
    return usage();
  }
  if(cmd=="update-serverlist"){
    if(argc<4) return usage();
    ed2k::net::IoRuntime rt;
    int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::infra::HTTPDownload http(rt.executor());
      auto r = co_await http.fetch(argv[2], argv[3], std::chrono::milliseconds(15000));
      if(!r){ std::printf("error: %s\n", r.error().message().c_str()); rc=1; }
      else std::printf("updated %s\n", argv[3]);
      rt.stop(); co_return;
    }, asio::detached);
    rt.run(); return rc;
  }
  if(cmd=="stats"){
    if(argc<3) return usage();
    auto stats = ed2k::infra::Statistics::load(argv[2]);
    if(!stats){ std::printf("error: %s\n", stats.error().message().c_str()); return 1; }
    const auto& s = stats->cumulative();
    std::printf("uploaded=%llu downloaded=%llu server_connections=%llu failed_connections=%llu kad_packets=%llu sources=%llu files=%llu\n",
                static_cast<unsigned long long>(s.uploaded_bytes),
                static_cast<unsigned long long>(s.downloaded_bytes),
                static_cast<unsigned long long>(s.server_connections),
                static_cast<unsigned long long>(s.failed_connections),
                static_cast<unsigned long long>(s.kad_packets_sent),
                static_cast<unsigned long long>(s.sources_seen),
                static_cast<unsigned long long>(s.files_completed));
    return 0;
  }
  if(cmd=="login"){
    if(argc<3) return usage();
    std::optional<ed2k::app::ServerTarget> ov;
    std::string metpath = argv[2];
    for(int i=3;i<argc;++i){ std::string a=argv[i]; if(a.rfind("--ip:",0)==0){ auto ip=IPv4::from_dotted(a.substr(4)); if(ip){ ed2k::app::ServerTarget t; t.ip=*ip; ov=t; } } else if(a.rfind("--port:",0)==0 && ov){ ov->port=std::uint16_t(std::stoi(a.substr(7))); } }
    auto metbytes = read_all(metpath.c_str());
    auto global_filter = load_cli_ip_filter(globals, *startup_prefs);
    if(!global_filter){ std::printf("error: %s\n", global_filter.error().message().c_str()); return 1; }
    ed2k::net::IoRuntime rt;
    auto p = cli_login_params(*startup_prefs);
    std::optional<ed2k::server::LoginResult> res;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      auto r = co_await ed2k::app::login_with_rotation(
        rt.executor(), metbytes, ov, p,
        std::chrono::milliseconds(startup_prefs->connect_timeout_ms),
        globals.proxy, *global_filter, startup_prefs->ip_filter_level);
      if(r) res = r->result;
      else std::printf("error: %s\n", r.error().message().c_str());
      rt.stop(); co_return;
    }, asio::detached);
    rt.run();
    if(!res) return 1;
    std::printf("client_id=0x%08X high_id=%d flags=0x%X\n", res->client_id, res->high_id?1:0, res->flags);
    return 0;
  }
  if(cmd=="search"){
    if(argc<4) return usage();
    auto metbytes = read_all(argv[2]);
    std::string kw = argv[3];
    auto global_filter = load_cli_ip_filter(globals, *startup_prefs);
    if(!global_filter){ std::printf("error: %s\n", global_filter.error().message().c_str()); return 1; }
    ed2k::net::IoRuntime rt;
    int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      auto lg = co_await ed2k::app::login_with_rotation(
        rt.executor(), metbytes, std::nullopt, cli_login_params(*startup_prefs),
        std::chrono::milliseconds(startup_prefs->connect_timeout_ms),
        globals.proxy, *global_filter, startup_prefs->ip_filter_level);
      if(!lg){ std::printf("error: %s\n", lg.error().message().c_str()); rc=1; rt.stop(); co_return; }
      auto sr = co_await lg->conn.search(ed2k::server::parse_keyword_query(kw),
                                         std::chrono::milliseconds(15000));
      if(!sr){ std::printf("error: %s\n", sr.error().message().c_str()); rc=1; rt.stop(); co_return; }
      for(const auto& it : *sr)
        std::printf("%s  %12llu  %s\n", it.hash.to_hex().c_str(), (unsigned long long)it.size, it.name.c_str());
      std::printf("(%zu results)\n", sr->size());
      rt.stop(); co_return;
    }, asio::detached);
    rt.run(); return rc;
  }
  if(cmd=="sources"){
    if(argc<4) return usage();
    auto metbytes = read_all(argv[2]);
    auto pl = parse_link(argv[3]);
    if(!pl){ std::printf("error: %s\n", pl.error().message().c_str()); return 1; }
    auto* f = std::get_if<Ed2kFileLink>(&*pl);
    if(!f){ std::printf("error: not a file link\n"); return 1; }
    auto global_filter = load_cli_ip_filter(globals, *startup_prefs);
    if(!global_filter){ std::printf("error: %s\n", global_filter.error().message().c_str()); return 1; }
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      auto lg = co_await ed2k::app::login_with_rotation(
        rt.executor(), metbytes, std::nullopt, cli_login_params(*startup_prefs),
        std::chrono::milliseconds(startup_prefs->connect_timeout_ms),
        globals.proxy, *global_filter, startup_prefs->ip_filter_level);
      if(!lg){ std::printf("error: %s\n", lg.error().message().c_str()); rc=1; rt.stop(); co_return; }
      auto gs = co_await lg->conn.get_sources(f->hash, f->size, std::chrono::milliseconds(15000));
      if(!gs){ std::printf("error: %s\n", gs.error().message().c_str()); rc=1; rt.stop(); co_return; }
      for(const auto& s : gs->sources)
        std::printf("%s  id=0x%08X  port=%u  %s\n", IPv4::from_wire(s.id).to_dotted().c_str(), s.id, s.port, s.low_id()?"LowID":"HighID");
      std::printf("(%zu sources)\n", gs->sources.size());
      rt.stop(); co_return;
    }, asio::detached);
    rt.run(); return rc;
  }
  if(cmd=="publish"){
    if(argc<3) return usage();
    std::filesystem::path dir = argv[2];
    std::vector<std::byte> metbytes;
    std::optional<ed2k::app::ServerTarget> ov;
    for(int i=3;i<argc;++i){
      std::string a=argv[i];
      if(a.rfind("--server:",0)==0){
        metbytes = read_all(a.substr(9).c_str());
      } else if(a.rfind("--ip:",0)==0){
        auto ip=IPv4::from_dotted(a.substr(5));
        if(ip){ ed2k::app::ServerTarget t; t.ip=*ip; ov=t; }
      } else if(a.rfind("--port:",0)==0){
        if(ov) ov->port=std::uint16_t(std::stoi(a.substr(7)));
      }
    }
    ed2k::share::KnownFileDB db;
    auto scan = db.scan_dir(dir);
    if(!scan){ std::printf("error: %s\n", scan.error().message().c_str()); return 1; }
    if(db.files().empty()){ std::printf("error: no regular files in %s\n", dir.string().c_str()); return 1; }
    auto global_filter = load_cli_ip_filter(globals, *startup_prefs);
    if(!global_filter){ std::printf("error: %s\n", global_filter.error().message().c_str()); return 1; }
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      auto lg = co_await ed2k::app::login_with_rotation(
        rt.executor(), metbytes, ov, cli_login_params(*startup_prefs),
        std::chrono::milliseconds(startup_prefs->connect_timeout_ms),
        globals.proxy, *global_filter, startup_prefs->ip_filter_level);
      if(!lg){ std::printf("error: %s\n", lg.error().message().c_str()); rc=1; rt.stop(); co_return; }
      auto pr = co_await lg->conn.publish_files(db.files());
      if(!pr){ std::printf("error: %s\n", pr.error().message().c_str()); rc=1; }
      else std::printf("published %zu files\n", db.files().size());
      lg->conn.close();
      rt.stop(); co_return;
    }, asio::detached);
    rt.run(); return rc;
  }
  if(cmd=="comment"){
    if(argc<3) return usage();
    auto pl = parse_link(argv[2]);
    if(!pl){ std::printf("error: %s\n", pl.error().message().c_str()); return 1; }
    auto* f = std::get_if<Ed2kFileLink>(&*pl);
    if(!f){ std::printf("error: not a file link\n"); return 1; }
    std::optional<unsigned> rating;
    std::string comment;
    std::optional<std::pair<IPv4, std::uint16_t>> peer;
    std::optional<UserHash> peer_hash;
    bool invalid_peer_hash = false;
    bool missing_peer_hash_value = false;
    for(int i=3;i<argc;++i){
      std::string a=argv[i];
      if(a=="--rating" && i+1<argc) rating = static_cast<unsigned>(std::stoul(argv[++i]));
      else if(a.rfind("--rating:",0)==0) rating = static_cast<unsigned>(std::stoul(a.substr(9)));
      else if(a=="--comment" && i+1<argc) comment = argv[++i];
      else if(a.rfind("--comment:",0)==0) comment = a.substr(10);
      else if(a.rfind("--peer:",0)==0) peer = parse_peer(a.substr(7));
      else if(a=="--peer-hash") {
        if(i+1>=argc) missing_peer_hash_value = true;
        else {
          auto parsed = UserHash::from_hex(argv[++i]);
          if(parsed) peer_hash = *parsed; else invalid_peer_hash = true;
        }
      }
      else if(a.rfind("--peer-hash:",0)==0) {
        auto parsed = UserHash::from_hex(a.substr(12));
        if(parsed) peer_hash = *parsed; else invalid_peer_hash = true;
      }
    }
    if(!rating || *rating > 5){ std::printf("error: rating must be 0..5\n"); return 1; }
    if(comment.empty()){ std::printf("error: comment required\n"); return 1; }
    if(missing_peer_hash_value){ std::printf("error: --peer-hash requires a value\n"); return 1; }
    if(invalid_peer_hash){ std::printf("error: --peer-hash must be a 32-hex user hash\n"); return 1; }
    auto payload = ed2k::peer::encode_file_desc(static_cast<std::uint8_t>(*rating), comment);
    if(!peer){
      std::printf("file=%s rating=%u comment=%s payload=%s\n",
        f->hash.to_hex().c_str(), *rating, comment.c_str(), hex_bytes(payload).c_str());
      return 0;
    }
    const auto obfuscation_policy = cli_obfuscation_policy(*startup_prefs);
    if(obfuscation_policy != ed2k::peer::ObfuscationPolicy::disabled && !peer_hash){
      std::printf("error: obfuscation for comment peer requires --peer-hash:<32-hex-user-hash>\n");
      return 1;
    }
    auto global_filter = load_cli_ip_filter(globals, *startup_prefs);
    if(!global_filter){ std::printf("error: %s\n", global_filter.error().message().c_str()); return 1; }
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::peer::C2CConnection c(rt.executor());
      c.set_ip_filter(*global_filter, startup_prefs->ip_filter_level);
      const auto host = peer->first.host();
      const auto wire = ((host & 0xFFu) << 24) | ((host & 0xFF00u) << 8) |
                        ((host & 0xFF0000u) >> 8) | ((host & 0xFF000000u) >> 24);
      auto cr = co_await c.connect(
        ed2k::peer::PeerIdentity{{wire, peer->second}, peer_hash},
        obfuscation_policy, std::chrono::milliseconds(15000));
      if(!cr){ std::printf("error: %s\n", cr.error().message().c_str()); rc=1; rt.stop(); co_return; }
      auto hs = co_await c.handshake(cli_hello(obfuscation_policy),
                                     std::chrono::milliseconds(15000));
      if(!hs){ std::printf("error: %s\n", hs.error().message().c_str()); rc=1; rt.stop(); co_return; }
      auto fs = co_await c.request_file(f->hash, std::chrono::milliseconds(15000));
      if(!fs){ std::printf("error: %s\n", fs.error().message().c_str()); rc=1; rt.stop(); co_return; }
      auto sr = co_await c.send_file_desc(static_cast<std::uint8_t>(*rating), comment);
      if(!sr){ std::printf("error: %s\n", sr.error().message().c_str()); rc=1; }
      else std::printf("sent comment for %s\n", f->hash.to_hex().c_str());
      c.close();
      rt.stop(); co_return;
    }, asio::detached);
    rt.run(); return rc;
  }
  if(cmd=="kad-bootstrap"){
    if(argc<3) return usage();
    auto contacts = load_kad_nodes(argv[2]);
    if(!contacts){ std::printf("error: %s\n", contacts.error().message().c_str()); return 1; }
    auto global_filter = load_cli_ip_filter(globals, *startup_prefs);
    if(!global_filter){ std::printf("error: %s\n", global_filter.error().message().c_str()); return 1; }
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::kad::KadNetwork network(rt.executor(), cli_kad_options(
        startup_prefs->tcp_port, *global_filter, startup_prefs->ip_filter_level));
      auto bootstrapped = co_await bootstrap_if_needed(network, *contacts, k_kad_bootstrap_timeout);
      if(!bootstrapped){ std::printf("error: %s\n", bootstrapped.error().message().c_str()); rc=1; }
      else {
        std::printf("kad contacts: loaded=%zu routing=%zu udp_port=%u\n",
          contacts->size(), network.routing_table().size(), network.self_contact().udp_port);
      }
      network.close();
      rt.stop(); co_return;
    }, asio::detached);
    rt.run(); return rc;
  }
  if(cmd=="kad-search"){
    if(argc<4) return usage();
    auto contacts = load_kad_nodes(argv[2]);
    if(!contacts){ std::printf("error: %s\n", contacts.error().message().c_str()); return 1; }
    // 多词: 最长词定位 + 其余词本地过滤(与 Session::kad_search 同口径)
    const auto query = ed2k::kad::build_keyword_query(argv[3]);
    const auto key = query.valid ? query.target : ed2k::kad::keyword_id(argv[3]);
    auto global_filter = load_cli_ip_filter(globals, *startup_prefs);
    if(!global_filter){ std::printf("error: %s\n", global_filter.error().message().c_str()); return 1; }
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::kad::KadNetwork network(rt.executor(), cli_kad_options(
        startup_prefs->tcp_port, *global_filter, startup_prefs->ip_filter_level));
      auto bootstrapped = co_await bootstrap_if_needed(network, *contacts, k_kad_bootstrap_timeout);
      if(!bootstrapped){ std::printf("error: %s\n", bootstrapped.error().message().c_str()); rc=1; network.close(); rt.stop(); co_return; }
      auto peers = network.routing_table().closest_to(key, ed2k::kad::KBucket::capacity);
      if(peers.empty()){
        std::printf("(0 results)\n");
        network.close(); rt.stop(); co_return;
      }
      auto results = co_await network.search_keyword(peers, key, k_kad_request_timeout);
      if(!results){ std::printf("error: %s\n", results.error().message().c_str()); rc=1; }
      else {
        std::size_t shown = 0;
        for(const auto& entry : *results){
          if(query.valid && !ed2k::kad::name_contains_all(ed2k::kad::file_name(entry), query.filters))
            continue;
          std::printf("%s  %12llu  %s\n", entry.answer_id.to_hex().c_str(),
            (unsigned long long)ed2k::kad::file_size(entry), ed2k::kad::file_name(entry).c_str());
          ++shown;
        }
        std::printf("(%zu results)\n", shown);
      }
      network.close();
      rt.stop(); co_return;
    }, asio::detached);
    rt.run(); return rc;
  }
  if(cmd=="kad-find-sources"){
    if(argc<4) return usage();
    auto contacts = load_kad_nodes(argv[2]);
    if(!contacts){ std::printf("error: %s\n", contacts.error().message().c_str()); return 1; }
    auto pl = parse_link(argv[3]);
    if(!pl){ std::printf("error: %s\n", pl.error().message().c_str()); return 1; }
    auto* f = std::get_if<Ed2kFileLink>(&*pl);
    if(!f){ std::printf("error: not a file link\n"); return 1; }
    const auto file_id = kad_id_from_hash(f->hash);
    auto global_filter = load_cli_ip_filter(globals, *startup_prefs);
    if(!global_filter){ std::printf("error: %s\n", global_filter.error().message().c_str()); return 1; }
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::kad::KadNetwork network(rt.executor(), cli_kad_options(
        startup_prefs->tcp_port, *global_filter, startup_prefs->ip_filter_level));
      auto bootstrapped = co_await bootstrap_if_needed(network, *contacts, k_kad_bootstrap_timeout);
      if(!bootstrapped){ std::printf("error: %s\n", bootstrapped.error().message().c_str()); rc=1; network.close(); rt.stop(); co_return; }
      auto peers = network.routing_table().closest_to(file_id, ed2k::kad::KBucket::capacity);
      if(peers.empty()){
        std::printf("(0 sources)\n");
        network.close(); rt.stop(); co_return;
      }
      auto sources = co_await network.find_sources(peers, file_id, f->size, k_kad_request_timeout);
      if(!sources){ std::printf("error: %s\n", sources.error().message().c_str()); rc=1; }
      else {
        for(const auto& entry : *sources){
          auto ip = ed2k::kad::source_ip(entry);
          std::printf("%s  tcp=%u udp=%u type=%u id=%s\n",
            ip ? ip->to_dotted().c_str() : "-",
            ed2k::kad::source_tcp_port(entry),
            ed2k::kad::source_udp_port(entry),
            ed2k::kad::source_type(entry),
            entry.answer_id.to_hex().c_str());
        }
        std::printf("(%zu sources)\n", sources->size());
      }
      network.close();
      rt.stop(); co_return;
    }, asio::detached);
    rt.run(); return rc;
  }
  if(cmd=="kad-publish"){
    if(argc<4) return usage();
    auto contacts = load_kad_nodes(argv[2]);
    if(!contacts){ std::printf("error: %s\n", contacts.error().message().c_str()); return 1; }
    std::filesystem::path dir = argv[3];
    std::uint16_t tcp_port = startup_prefs->tcp_port;
    for(int i=4;i<argc;++i){
      std::string a=argv[i];
      if(a.rfind("--port:",0)==0) tcp_port=std::uint16_t(std::stoi(a.substr(7)));
    }
    ed2k::share::KnownFileDB db;
    auto scan = db.scan_dir(dir);
    if(!scan){ std::printf("error: %s\n", scan.error().message().c_str()); return 1; }
    auto global_filter = load_cli_ip_filter(globals, *startup_prefs);
    if(!global_filter){ std::printf("error: %s\n", global_filter.error().message().c_str()); return 1; }
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::kad::KadNetwork network(rt.executor(), cli_kad_options(
        tcp_port, *global_filter, startup_prefs->ip_filter_level));
      auto bootstrapped = co_await bootstrap_if_needed(network, *contacts, k_kad_bootstrap_timeout);
      if(!bootstrapped){ std::printf("error: %s\n", bootstrapped.error().message().c_str()); rc=1; network.close(); rt.stop(); co_return; }
      std::size_t packets = 0;
      for(const auto& file : db.files()){
        const auto file_id = kad_id_from_hash(file.hash);
        auto source = kad_source_entry(file, tcp_port, network.self_contact().udp_port);
        auto source_peers = network.routing_table().closest_to(file_id, ed2k::kad::KBucket::capacity);
        for(const auto& peer : source_peers){
          auto sent = co_await network.publish_source(peer, file_id, source, k_kad_request_timeout);
          if(sent) ++packets;
        }

        for(const auto& keyword : ed2k::kad::keywords_for_name(file.name)){
          const auto key = ed2k::kad::keyword_id(keyword);
          std::vector<ed2k::kad::KadSearchEntry> entries{kad_file_entry(file)};
          auto key_peers = network.routing_table().closest_to(key, ed2k::kad::KBucket::capacity);
          for(const auto& peer : key_peers){
            auto sent = co_await network.publish_keyword(peer, key, entries, k_kad_request_timeout);
            if(sent) ++packets;
          }
        }
      }
      std::printf("kad published files=%zu packets=%zu\n", db.files().size(), packets);
      network.close();
      rt.stop(); co_return;
    }, asio::detached);
    rt.run(); return rc;
  }
  if(cmd=="download"){
    if(argc<3) return usage();
    auto link_s = std::string(argv[2]);
    auto pl = parse_link(link_s);
    if(!pl){ std::printf("error: %s\n", pl.error().message().c_str()); return 1; }
    auto* f = std::get_if<Ed2kFileLink>(&*pl);
    if(!f){ std::printf("error: not a file link\n"); return 1; }
    std::filesystem::path out = f->name.empty() ? "download.bin" : f->name;
    std::optional<ed2k::app::ServerTarget> ov;
    // --server:PATH reads server.met bytes; empty (default) -> download_link
    // falls back to its internal fallback server list.
    std::vector<std::byte> metbytes;
    for(int i=3;i<argc;++i){ std::string a=argv[i];
      if(a.rfind("--out:",0)==0) out = a.substr(6);
      else if(a.rfind("--server:",0)==0){ metbytes = read_all(a.substr(9).c_str()); }
    }
    auto global_filter = load_cli_ip_filter(globals, *startup_prefs);
    if(!global_filter){ std::printf("error: %s\n", global_filter.error().message().c_str()); return 1; }
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::app::DownloadOpts o;
      o.out_path=out;
      o.per_server_timeout=std::chrono::milliseconds(startup_prefs->connect_timeout_ms);
      o.total_timeout=std::chrono::seconds(300);
      o.client_port=startup_prefs->tcp_port;
      o.proxy=globals.proxy;
      o.ip_filter=*global_filter;
      o.ip_filter_level=startup_prefs->ip_filter_level;
      o.obfuscation_policy=cli_obfuscation_policy(*startup_prefs);
      o.local_user_hash=cli_user_hash();
      auto r = co_await ed2k::app::download_link(rt.executor(), *f, metbytes, ov, o);
      if(!r){ std::printf("error: %s\n", r.error().message().c_str()); rc=1; }
      else std::printf("downloaded %s\n", out.string().c_str());
      rt.stop(); co_return;
    }, asio::detached);
    rt.run(); return rc;
  }
  return usage();
}
