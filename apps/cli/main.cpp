#include <cstdio>
#include <span>
#include <string>
#include <vector>
#include <fstream>
#include <chrono>
#include "ed2k/version.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "ed2k/metfile/server_met.hpp"
#include "ed2k/app/server_session.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/server/connection.hpp"
#include "ed2k/server/search_query.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
namespace asio = boost::asio;
using namespace ed2k;
static int usage(){ std::puts("usage: ed2k-tool hash <file> [--aich] [--red]\n"
  "       ed2k-tool serverlist <server.met>\n"
  "       ed2k-tool parse <ed2k-link>\n"
  "       ed2k-tool login <server.met> [--ip:x.x.x.x] [--port:n]\n"
  "       ed2k-tool search <server.met> <keyword>\n"
  "       ed2k-tool sources <server.met> <ed2k-link>\n"
  "       ed2k-tool download <ed2k-link> [--out:PATH] [--server:server.met]"); return 2; }
static std::vector<std::byte> read_all(const char* p){
  std::ifstream f(p,std::ios::binary); std::vector<std::byte> v;
  f.seekg(0,std::ios::end); auto n=f.tellg(); f.seekg(0);
  if(n>0){ v.resize(std::size_t(n)); f.read(reinterpret_cast<char*>(v.data()),n); } return v;
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
        std::printf("%s  id=0x%08X  port=%u  %s\n", IPv4{s.id}.to_dotted().c_str(), s.id, s.port, s.low_id()?"LowID":"HighID");
      std::printf("(%zu sources)\n", gs->sources.size());
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
