#include "crypto/sha1.hpp"
#include <cstring>
namespace ed2k::crypto {
namespace { inline std::uint32_t rol(std::uint32_t x,int s){ return (x<<s)|(x>>(32-s)); } }
void SHA1::reset() noexcept {
  state_[0]=0x67452301u;state_[1]=0xEFCDAB89u;state_[2]=0x98BADCFEu;
  state_[3]=0x10325476u;state_[4]=0xC3D2E1F0u; bitlen_=0; buflen_=0;
}
void SHA1::transform(const std::uint8_t b[64]) noexcept {
  std::uint32_t w[80];
  for(int i=0;i<16;++i)
    w[i]=((std::uint32_t)b[i*4]<<24)|((std::uint32_t)b[i*4+1]<<16)|((std::uint32_t)b[i*4+2]<<8)|b[i*4+3];
  for(int i=16;i<80;++i) w[i]=rol(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
  std::uint32_t a=state_[0],bb=state_[1],c=state_[2],d=state_[3],e=state_[4];
  for(int i=0;i<80;++i){
    std::uint32_t f,k;
    if(i<20){f=(bb&c)|(~bb&d);k=0x5A827999u;}
    else if(i<40){f=bb^c^d;k=0x6ED9EBA1u;}
    else if(i<60){f=(bb&c)|(bb&d)|(c&d);k=0x8F1BBCDCu;}
    else{f=bb^c^d;k=0xCA62C1D6u;}
    std::uint32_t t=rol(a,5)+f+e+k+w[i]; e=d;d=c;c=rol(bb,30);bb=a;a=t;
  }
  state_[0]+=a;state_[1]+=bb;state_[2]+=c;state_[3]+=d;state_[4]+=e;
}
void SHA1::update(std::span<const std::byte> data) noexcept {
  const std::uint8_t* p=reinterpret_cast<const std::uint8_t*>(data.data());
  std::size_t n=data.size(); bitlen_+=(std::uint64_t)n*8;
  while(n>0){ std::size_t take=64-buflen_; if(take>n)take=n;
    std::memcpy(buf_+buflen_,p,take); buflen_+=take; p+=take; n-=take;
    if(buflen_==64){ transform(buf_); buflen_=0; } }
}
std::array<std::byte,20> SHA1::finish() noexcept {
  std::uint64_t bits=bitlen_;
  std::uint8_t pad=0x80; update({reinterpret_cast<std::byte*>(&pad),1});
  std::uint8_t zero=0; while(buflen_!=56) update({reinterpret_cast<std::byte*>(&zero),1});
  std::uint8_t len[8]; for(int i=0;i<8;++i) len[i]=(std::uint8_t)(bits>>(8*(7-i)));
  update({reinterpret_cast<std::byte*>(len),8});
  std::array<std::byte,20> out;
  for(int i=0;i<5;++i){ out[i*4+0]=std::byte((state_[i]>>24)&0xff); out[i*4+1]=std::byte((state_[i]>>16)&0xff);
    out[i*4+2]=std::byte((state_[i]>>8)&0xff); out[i*4+3]=std::byte(state_[i]&0xff); }
  reset(); return out;
}
std::array<std::byte,20> sha1(std::span<const std::byte> d) noexcept { SHA1 s; s.update(d); return s.finish(); }
}
