#include <cstdio>
#include <span>
#include <string>
#include <vector>
#include <fstream>
#include "ed2k/version.hpp"
#include "ed2k/hash/ed2k_hasher.hpp"
#include "ed2k/hash/aich_hasher.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "ed2k/metfile/server_met.hpp"
using namespace ed2k;
static int usage(){ std::puts("usage: ed2k-tool hash <file> [--aich] [--red]\n"
  "       ed2k-tool serverlist <server.met>\n"
  "       ed2k-tool parse <ed2k-link>"); return 2; }
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
  return usage();
}
