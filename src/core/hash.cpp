#include "ed2k/core/hash.hpp"
#include <cstdio>
namespace ed2k {
namespace {
int hexval(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10;
  if(c>='A'&&c<='F')return c-'A'+10; return -1; }
}
tl::expected<MD4Hash,std::error_code> MD4Hash::from_hex(std::string_view s){
  if(s.size()!=32) return tl::unexpected(make_error_code(errc::invalid_hex));
  std::array<std::byte,16> out{};
  for(int i=0;i<16;++i){ int hi=hexval(s[i*2]),lo=hexval(s[i*2+1]);
    if(hi<0||lo<0) return tl::unexpected(make_error_code(errc::invalid_hex));
    out[i]=std::byte((hi<<4)|lo); }
  return MD4Hash::from_bytes(out);
}
std::string MD4Hash::to_hex() const {
  static const char* k="0123456789abcdef"; std::string s; s.reserve(32);
  for(auto b:b_){auto v=std::to_integer<unsigned>(b); s+=k[v>>4]; s+=k[v&15];} return s;
}
namespace {
const char* B32="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
int b32val(char c){ for(int i=0;i<32;++i) if(B32[i]==c) return i; return -1; }
}
std::string AICHHash::to_base32() const {
  std::string out; int bits=0; std::uint32_t acc=0;
  for(auto by:b_){ acc=(acc<<8)|std::to_integer<unsigned>(by); bits+=8;
    while(bits>=5){ bits-=5; out+=B32[(acc>>bits)&31]; } }
  if(bits>0) out+=B32[(acc<<(5-bits))&31];
  return out; // 20 字节 → 32 字符
}
tl::expected<AICHHash,std::error_code> AICHHash::from_base32(std::string_view s){
  std::array<std::byte,20> out{}; int bits=0; std::uint32_t acc=0; std::size_t oi=0;
  for(char c:s){ int v=b32val(c); if(v<0) return tl::unexpected(make_error_code(errc::invalid_base32));
    acc=(acc<<5)|v; bits+=5; if(bits>=8){ bits-=8; if(oi>=20) return tl::unexpected(make_error_code(errc::invalid_base32));
      out[oi++]=std::byte((acc>>bits)&0xff); } }
  if(oi!=20) return tl::unexpected(make_error_code(errc::invalid_base32));
  return AICHHash::from_bytes(out);
}
tl::expected<IPv4,std::error_code> IPv4::from_dotted(std::string_view s){
  unsigned a,b,c,d; char extra;
  std::string str(s);
  if(std::sscanf(str.c_str(),"%u.%u.%u.%u%c",&a,&b,&c,&d,&extra)!=4)
    return tl::unexpected(make_error_code(errc::malformed_link));
  if(a>255||b>255||c>255||d>255) return tl::unexpected(make_error_code(errc::malformed_link));
  return IPv4::from_host((a<<24)|(b<<16)|(c<<8)|d);
}
std::string IPv4::to_dotted() const {
  char buf[16]; std::snprintf(buf,sizeof buf,"%u.%u.%u.%u",
    (value_>>24)&0xff,(value_>>16)&0xff,(value_>>8)&0xff,value_&0xff); return buf;
}
}
