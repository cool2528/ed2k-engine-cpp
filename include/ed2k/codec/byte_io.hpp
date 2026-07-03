#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include "ed2k/core/hash.hpp"
namespace ed2k::codec {
class ByteReader {
  std::span<const std::byte> buf_; std::size_t pos_=0; bool ok_=true;
  bool need(std::size_t n){ if(!ok_||pos_+n>buf_.size()){ ok_=false; return false;} return true; }
 public:
  explicit ByteReader(std::span<const std::byte> b):buf_(b){}
  bool ok() const { return ok_; }
  std::size_t remaining() const { return ok_? buf_.size()-pos_ : 0; }
  std::size_t pos() const { return pos_; }
  std::uint8_t  u8(){ if(!need(1))return 0; return std::to_integer<std::uint8_t>(buf_[pos_++]); }
  std::uint16_t u16(){ if(!need(2))return 0; std::uint16_t v=std::to_integer<std::uint8_t>(buf_[pos_])
    |(std::uint16_t(std::to_integer<std::uint8_t>(buf_[pos_+1]))<<8); pos_+=2; return v; }
  std::uint32_t u32(){ if(!need(4))return 0; std::uint32_t v=0; for(int i=0;i<4;++i)
    v|=std::uint32_t(std::to_integer<std::uint8_t>(buf_[pos_+i]))<<(8*i); pos_+=4; return v; }
  std::uint32_t u32_be(){ if(!need(4))return 0; std::uint32_t v=0; for(int i=0;i<4;++i)
    v=(v<<8)|std::to_integer<std::uint8_t>(buf_[pos_+i]); pos_+=4; return v; }   // 网络序 IP（a.b.c.d，a 在高位）
  std::uint64_t u64(){ if(!need(8))return 0; std::uint64_t v=0; for(int i=0;i<8;++i)
    v|=std::uint64_t(std::to_integer<std::uint8_t>(buf_[pos_+i]))<<(8*i); pos_+=8; return v; }
  std::string string16(){ std::uint16_t n=u16(); if(!need(n))return {};
    std::string s(reinterpret_cast<const char*>(buf_.data()+pos_),n); pos_+=n; return s; }
  MD4Hash hash16(){ if(!need(16))return {}; std::array<std::byte,16> h;
    for(int i=0;i<16;++i)h[i]=buf_[pos_+i]; pos_+=16; return MD4Hash::from_bytes(h); }
  std::array<std::byte,20> hash20(){ std::array<std::byte,20> h{}; if(!need(20))return h;
    for(int i=0;i<20;++i)h[i]=buf_[pos_+i]; pos_+=20; return h; }
  std::span<const std::byte> blob(std::size_t n){ if(!need(n))return {};
    auto s=buf_.subspan(pos_,n); pos_+=n; return s; }
};
class ByteWriter {
  std::vector<std::byte> out_;
 public:
  void u8(std::uint8_t v){ out_.push_back(std::byte(v)); }
  void u16(std::uint16_t v){ for(int i=0;i<2;++i) out_.push_back(std::byte((v>>(8*i))&0xff)); }
  void u32(std::uint32_t v){ for(int i=0;i<4;++i) out_.push_back(std::byte((v>>(8*i))&0xff)); }
  void u32_be(std::uint32_t v){ for(int i=3;i>=0;--i) out_.push_back(std::byte((v>>(8*i))&0xff)); } // 网络序 IP（a.b.c.d）
  void u64(std::uint64_t v){ for(int i=0;i<8;++i) out_.push_back(std::byte((v>>(8*i))&0xff)); }
  void string16(std::string_view s){ u16(std::uint16_t(s.size()));
    for(char c:s) out_.push_back(std::byte((unsigned char)c)); }
  void hash16(const MD4Hash& h){ for(auto b:h.bytes()) out_.push_back(b); }
  void hash20(std::span<const std::byte,20> h){ for(auto b:h) out_.push_back(b); }
  void blob(std::span<const std::byte> b){ for(auto x:b) out_.push_back(x); }
  std::vector<std::byte> take(){ return std::move(out_); }
};
}
