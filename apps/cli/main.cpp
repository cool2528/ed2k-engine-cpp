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
#include "ed2k/version.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "ed2k/metfile/server_met.hpp"
#include "ed2k/app/server_session.hpp"
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
  "       ed2k-tool serverlist <server.met>\n"
  "       ed2k-tool parse <ed2k-link>\n"
  "       ed2k-tool login <server.met> [--ip:x.x.x.x] [--port:n]\n"
  "       ed2k-tool search <server.met> <keyword>\n"
  "       ed2k-tool sources <server.met> <ed2k-link>\n"
  "       ed2k-tool publish <dir> [--server:server.met] [--ip:x.x.x.x] [--port:n]\n"
  "       ed2k-tool comment <ed2k-link> --rating:n --comment:text [--peer:ip:port]\n"
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
static ed2k::peer::HelloInfo cli_hello(){
  ed2k::peer::HelloInfo h;
  h.nickname = "ed2k-tool";
  h.version = 0x3C;
  h.port = 4662;
  h.user_hash = *UserHash::from_hex("0123456789abcdeffedcba9876543210");
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
static ed2k::kad::KadNetworkOptions cli_kad_options(std::uint16_t tcp_port){
  auto user_hash = cli_user_hash();
  return ed2k::kad::KadNetworkOptions{
    .id = ed2k::kad::KadID::from_user_hash(user_hash, 1),
    .ip = ed2k::IPv4::from_dotted("0.0.0.0").value(),
    .tcp_port = tcp_port,
    .version = ed2k::kad::kad2_version,
    .user_hash = ed2k::kad::KadID::from_bytes(user_hash.bytes()),
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
  if(argc<2) return usage();
  std::string cmd=argv[1];
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
  if(cmd=="login"){
    if(argc<3) return usage();
    std::optional<ed2k::app::ServerTarget> ov;
    std::string metpath = argv[2];
    for(int i=3;i<argc;++i){ std::string a=argv[i]; if(a.rfind("--ip:",0)==0){ auto ip=IPv4::from_dotted(a.substr(4)); if(ip){ ed2k::app::ServerTarget t; t.ip=*ip; ov=t; } } else if(a.rfind("--port:",0)==0 && ov){ ov->port=std::uint16_t(std::stoi(a.substr(7))); } }
    auto metbytes = read_all(metpath.c_str());
    ed2k::net::IoRuntime rt;
    ed2k::server::LoginParams p; p.nickname="ed2k-tool"; p.client_port=4662;
    p.user_hash = *UserHash::from_hex("0123456789abcdeffedcba9876543210");
    std::optional<ed2k::server::LoginResult> res;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      auto r = co_await ed2k::app::login_with_rotation(rt.executor(), metbytes, ov, p, std::chrono::milliseconds(15000));
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
    ed2k::net::IoRuntime rt;
    int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      auto lg = co_await ed2k::app::login_with_rotation(rt.executor(), metbytes, std::nullopt, []{ ed2k::server::LoginParams p; p.nickname="ed2k-tool"; p.client_port=4662; p.user_hash=*UserHash::from_hex("0123456789abcdeffedcba9876543210"); return p; }(), std::chrono::milliseconds(15000));
      if(!lg){ std::printf("error: %s\n", lg.error().message().c_str()); rc=1; rt.stop(); co_return; }
      auto sr = co_await lg->conn.search(ed2k::server::Keyword{kw}, std::chrono::milliseconds(15000));
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
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::server::LoginParams p; p.nickname="ed2k-tool"; p.client_port=4662; p.user_hash=*UserHash::from_hex("0123456789abcdeffedcba9876543210");
      auto lg = co_await ed2k::app::login_with_rotation(rt.executor(), metbytes, std::nullopt, p, std::chrono::milliseconds(15000));
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
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::server::LoginParams p; p.nickname="ed2k-tool"; p.client_port=4662;
      p.user_hash=*UserHash::from_hex("0123456789abcdeffedcba9876543210");
      auto lg = co_await ed2k::app::login_with_rotation(rt.executor(), metbytes, ov, p, std::chrono::milliseconds(15000));
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
    for(int i=3;i<argc;++i){
      std::string a=argv[i];
      if(a=="--rating" && i+1<argc) rating = static_cast<unsigned>(std::stoul(argv[++i]));
      else if(a.rfind("--rating:",0)==0) rating = static_cast<unsigned>(std::stoul(a.substr(9)));
      else if(a=="--comment" && i+1<argc) comment = argv[++i];
      else if(a.rfind("--comment:",0)==0) comment = a.substr(10);
      else if(a.rfind("--peer:",0)==0) peer = parse_peer(a.substr(7));
    }
    if(!rating || *rating > 5){ std::printf("error: rating must be 0..5\n"); return 1; }
    if(comment.empty()){ std::printf("error: comment required\n"); return 1; }
    auto payload = ed2k::peer::encode_file_desc(static_cast<std::uint8_t>(*rating), comment);
    if(!peer){
      std::printf("file=%s rating=%u comment=%s payload=%s\n",
        f->hash.to_hex().c_str(), *rating, comment.c_str(), hex_bytes(payload).c_str());
      return 0;
    }
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::peer::C2CConnection c(rt.executor());
      auto cr = co_await c.connect(peer->first, peer->second, std::chrono::milliseconds(15000));
      if(!cr){ std::printf("error: %s\n", cr.error().message().c_str()); rc=1; rt.stop(); co_return; }
      auto hs = co_await c.handshake(cli_hello(), std::chrono::milliseconds(15000));
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
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::kad::KadNetwork network(rt.executor(), cli_kad_options(4662));
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
    const auto key = ed2k::kad::keyword_id(argv[3]);
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::kad::KadNetwork network(rt.executor(), cli_kad_options(4662));
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
        for(const auto& entry : *results)
          std::printf("%s  %12llu  %s\n", entry.answer_id.to_hex().c_str(),
            (unsigned long long)ed2k::kad::file_size(entry), ed2k::kad::file_name(entry).c_str());
        std::printf("(%zu results)\n", results->size());
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
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::kad::KadNetwork network(rt.executor(), cli_kad_options(4662));
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
    std::uint16_t tcp_port = 4662;
    for(int i=4;i<argc;++i){
      std::string a=argv[i];
      if(a.rfind("--port:",0)==0) tcp_port=std::uint16_t(std::stoi(a.substr(7)));
    }
    ed2k::share::KnownFileDB db;
    auto scan = db.scan_dir(dir);
    if(!scan){ std::printf("error: %s\n", scan.error().message().c_str()); return 1; }
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::kad::KadNetwork network(rt.executor(), cli_kad_options(tcp_port));
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
    ed2k::net::IoRuntime rt; int rc=0;
    asio::co_spawn(rt.context(), [&]() -> asio::awaitable<void>{
      ed2k::app::DownloadOpts o; o.out_path=out; o.total_timeout=std::chrono::seconds(300);
      auto r = co_await ed2k::app::download_link(rt.executor(), *f, metbytes, ov, o);
      if(!r){ std::printf("error: %s\n", r.error().message().c_str()); rc=1; }
      else std::printf("downloaded %s\n", out.string().c_str());
      rt.stop(); co_return;
    }, asio::detached);
    rt.run(); return rc;
  }
  return usage();
}
