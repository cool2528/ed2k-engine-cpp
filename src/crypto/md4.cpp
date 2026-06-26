#include "crypto/md4.hpp"
#include <cstring>
namespace ed2k::crypto {
namespace {
inline std::uint32_t rol(std::uint32_t x, int s){ return (x<<s)|(x>>(32-s)); }
inline std::uint32_t F(std::uint32_t x,std::uint32_t y,std::uint32_t z){ return (x&y)|(~x&z); }
inline std::uint32_t G(std::uint32_t x,std::uint32_t y,std::uint32_t z){ return (x&y)|(x&z)|(y&z); }
inline std::uint32_t H(std::uint32_t x,std::uint32_t y,std::uint32_t z){ return x^y^z; }
}
void MD4::reset() noexcept {
  state_[0]=0x67452301u; state_[1]=0xefcdab89u; state_[2]=0x98badcfeu; state_[3]=0x10325476u;
  bitlen_=0; buflen_=0;
}
void MD4::transform(const std::uint8_t b[64]) noexcept {
  std::uint32_t x[16];
  for (int i=0;i<16;++i)
    x[i]=(std::uint32_t)b[i*4]|((std::uint32_t)b[i*4+1]<<8)|((std::uint32_t)b[i*4+2]<<16)|((std::uint32_t)b[i*4+3]<<24);
  std::uint32_t a=state_[0],bb=state_[1],c=state_[2],d=state_[3];
  auto R1=[&](std::uint32_t&w,std::uint32_t xx,std::uint32_t yy,std::uint32_t zz,std::uint32_t k,int s){ w=rol(w+F(xx,yy,zz)+x[k],s); };
  auto R2=[&](std::uint32_t&w,std::uint32_t xx,std::uint32_t yy,std::uint32_t zz,std::uint32_t k,int s){ w=rol(w+G(xx,yy,zz)+x[k]+0x5a827999u,s); };
  auto R3=[&](std::uint32_t&w,std::uint32_t xx,std::uint32_t yy,std::uint32_t zz,std::uint32_t k,int s){ w=rol(w+H(xx,yy,zz)+x[k]+0x6ed9eba1u,s); };
  R1(a,bb,c,d,0,3);R1(d,a,bb,c,1,7);R1(c,d,a,bb,2,11);R1(bb,c,d,a,3,19);
  R1(a,bb,c,d,4,3);R1(d,a,bb,c,5,7);R1(c,d,a,bb,6,11);R1(bb,c,d,a,7,19);
  R1(a,bb,c,d,8,3);R1(d,a,bb,c,9,7);R1(c,d,a,bb,10,11);R1(bb,c,d,a,11,19);
  R1(a,bb,c,d,12,3);R1(d,a,bb,c,13,7);R1(c,d,a,bb,14,11);R1(bb,c,d,a,15,19);
  R2(a,bb,c,d,0,3);R2(d,a,bb,c,4,5);R2(c,d,a,bb,8,9);R2(bb,c,d,a,12,13);
  R2(a,bb,c,d,1,3);R2(d,a,bb,c,5,5);R2(c,d,a,bb,9,9);R2(bb,c,d,a,13,13);
  R2(a,bb,c,d,2,3);R2(d,a,bb,c,6,5);R2(c,d,a,bb,10,9);R2(bb,c,d,a,14,13);
  R2(a,bb,c,d,3,3);R2(d,a,bb,c,7,5);R2(c,d,a,bb,11,9);R2(bb,c,d,a,15,13);
  R3(a,bb,c,d,0,3);R3(d,a,bb,c,8,9);R3(c,d,a,bb,4,11);R3(bb,c,d,a,12,15);
  R3(a,bb,c,d,2,3);R3(d,a,bb,c,10,9);R3(c,d,a,bb,6,11);R3(bb,c,d,a,14,15);
  R3(a,bb,c,d,1,3);R3(d,a,bb,c,9,9);R3(c,d,a,bb,5,11);R3(bb,c,d,a,13,15);
  R3(a,bb,c,d,3,3);R3(d,a,bb,c,11,9);R3(c,d,a,bb,7,11);R3(bb,c,d,a,15,15);
  state_[0]+=a; state_[1]+=bb; state_[2]+=c; state_[3]+=d;
}
void MD4::update(std::span<const std::byte> data) noexcept {
  const std::uint8_t* p=reinterpret_cast<const std::uint8_t*>(data.data());
  std::size_t n=data.size(); bitlen_+=(std::uint64_t)n*8;
  while (n>0){
    std::size_t take=64-buflen_; if(take>n) take=n;
    std::memcpy(buf_+buflen_,p,take); buflen_+=take; p+=take; n-=take;
    if (buflen_==64){ transform(buf_); buflen_=0; }
  }
}
std::array<std::byte,16> MD4::finish() noexcept {
  std::uint64_t bits=bitlen_;
  std::uint8_t pad=0x80; update({reinterpret_cast<std::byte*>(&pad),1});
  std::uint8_t zero=0; while (buflen_!=56) update({reinterpret_cast<std::byte*>(&zero),1});
  std::uint8_t len[8]; for(int i=0;i<8;++i) len[i]=(std::uint8_t)(bits>>(8*i));
  update({reinterpret_cast<std::byte*>(len),8});
  std::array<std::byte,16> out;
  for (int i=0;i<4;++i){
    out[i*4+0]=std::byte(state_[i]&0xff); out[i*4+1]=std::byte((state_[i]>>8)&0xff);
    out[i*4+2]=std::byte((state_[i]>>16)&0xff); out[i*4+3]=std::byte((state_[i]>>24)&0xff);
  }
  reset(); return out;
}
std::array<std::byte,16> md4(std::span<const std::byte> data) noexcept {
  MD4 m; m.update(data); return m.finish();
}
}
