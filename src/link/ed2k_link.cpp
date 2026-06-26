#include "ed2k/link/ed2k_link.hpp"
#include <charconv>
#include <vector>
namespace ed2k {
namespace {
std::vector<std::string> split(std::string_view s, char d){
  std::vector<std::string> out; std::size_t i=0;
  while(true){ auto j=s.find(d,i); out.emplace_back(s.substr(i, j==std::string_view::npos? j : j-i));
    if(j==std::string_view::npos) break; i=j+1; }
  return out;
}
tl::unexpected<std::error_code> bad(){ return tl::unexpected(make_error_code(errc::malformed_link)); }
}
tl::expected<Ed2kLink,std::error_code> parse_link(std::string_view in){
  constexpr std::string_view pfx="ed2k://|";
  if(in.substr(0,pfx.size())!=pfx) return bad();
  auto parts=split(in, '|');
  // parts[0]="ed2k://", parts[1]=type, ...
  if(parts.size()<2) return bad();
  const std::string& type=parts[1];
  if(type=="file"){
    // ed2k://|file|name|size|hash|[opt...]|/
    if(parts.size()<6) return bad();
    Ed2kFileLink f; f.name=parts[2];
    auto& szs=parts[3];
    if(std::from_chars(szs.data(),szs.data()+szs.size(),f.size).ec!=std::errc{}) return bad();
    auto h=FileHash::from_hex(parts[4]); if(!h) return bad(); f.hash=*h;
    for(std::size_t i=5;i+1<parts.size();++i){            // 末项是 "/" 或空
      std::string_view seg=parts[i];
      if(seg.rfind("h=",0)==0){ auto a=AICHHash::from_base32(seg.substr(2)); if(a) f.aich=*a; }
      else if(seg.rfind("s=",0)==0){ f.sources.emplace_back(seg.substr(2)); }
      else if(seg.rfind("p=",0)==0){ for(auto& ph:split(seg.substr(2), ':')){
        auto x=PartHash::from_hex(ph); if(x) f.part_hashes.push_back(*x); } }
    }
    return Ed2kLink{f};
  }
  if(type=="server"){
    if(parts.size()<5) return bad();
    auto ip=IPv4::from_dotted(parts[2]); if(!ip) return bad();
    ServerLink s; s.ip=*ip;
    if(std::from_chars(parts[3].data(),parts[3].data()+parts[3].size(),s.port).ec!=std::errc{}) return bad();
    return Ed2kLink{s};
  }
  if(type=="serverlist"){
    if(parts.size()<4) return bad();
    return Ed2kLink{ServerListLink{parts[2]}};
  }
  return bad();
}
std::string to_string(const Ed2kFileLink& f){
  std::string s="ed2k://|file|"; s+=f.name; s+='|'; s+=std::to_string(f.size); s+='|';
  s+=f.hash.to_hex(); s+='|';
  if(f.aich){ s+="h="; s+=f.aich->to_base32(); s+='|'; }
  for(auto& src:f.sources){ s+="s="; s+=src; s+='|'; }
  s+='/'; return s;
}
}
