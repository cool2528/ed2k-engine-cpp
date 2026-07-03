#include "ed2k/codec/tag.hpp"
namespace ed2k::codec {
void write_tag(ByteWriter& w, const Tag& t){
  std::uint8_t type =
    std::holds_alternative<std::string>(t.value) ? tagtype::String :
    std::holds_alternative<MD4Hash>(t.value)     ? tagtype::Hash16 :
    std::holds_alternative<std::vector<std::byte>>(t.value) ? tagtype::Blob :
                                                   tagtype::Uint32;
  if(t.has_string_name()){
    w.u8(type); w.string16(t.name_str);
  } else {
    w.u8(type | tagtype::NameFlag); w.u8(t.name_id);
  }
  switch(type){
    case tagtype::String: w.string16(std::get<std::string>(t.value)); break;
    case tagtype::Hash16: w.hash16(std::get<MD4Hash>(t.value)); break;
    case tagtype::Uint32: w.u32(std::uint32_t(std::get<std::uint64_t>(t.value))); break;
    case tagtype::Blob: { auto& b=std::get<std::vector<std::byte>>(t.value);
      w.u32(std::uint32_t(b.size())); w.blob(b); } break;
  }
}
tl::expected<Tag,std::error_code> read_tag(ByteReader& r){
  std::uint8_t type=r.u8(); Tag t;
  if(type & tagtype::NameFlag){ type&=~tagtype::NameFlag; t.name_id=r.u8(); }
  else { t.name_str=r.string16(); }
  if(type >= tagtype::Str1 && type <= tagtype::Str16){
    // eMule 短字符串优化：type 即长度(1..16)，无长度前缀
    std::uint8_t n = static_cast<std::uint8_t>(type - tagtype::Str1 + 1);
    auto b = r.blob(n);
    t.value = std::string(reinterpret_cast<const char*>(b.data()), b.size());
  } else switch(type){
    case tagtype::String: t.value=r.string16(); break;
    case tagtype::Hash16: t.value=r.hash16(); break;
    case tagtype::Uint32: t.value=std::uint64_t(r.u32()); break;
    case tagtype::Uint16: t.value=std::uint64_t(r.u16()); break;
    case tagtype::Uint8:  t.value=std::uint64_t(r.u8()); break;
    case tagtype::Uint64: t.value=r.u64(); break;
    case tagtype::Float32: t.value=std::uint64_t(r.u32()); break; // 4 字节，位模式消费
    case tagtype::Blob: { std::uint32_t n=r.u32(); auto b=r.blob(n);
      t.value=std::vector<std::byte>(b.begin(),b.end()); } break;
    case tagtype::BSOB: { std::uint8_t n=r.u8(); auto b=r.blob(n);
      t.value=std::vector<std::byte>(b.begin(),b.end()); } break;
    default: return tl::unexpected(make_error_code(errc::unsupported_version));
  }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return t;
}
void write_taglist(ByteWriter& w, std::span<const Tag> tags){
  for(auto& t:tags) write_tag(w,t);
}
tl::expected<std::vector<Tag>,std::error_code> read_taglist(ByteReader& r, std::uint32_t count){
  if(count>100000) return tl::unexpected(make_error_code(errc::count_too_large));
  std::vector<Tag> out; out.reserve(count);
  for(std::uint32_t i=0;i<count;++i){ auto t=read_tag(r); if(!t) return tl::unexpected(t.error());
    out.push_back(std::move(*t)); }
  return out;
}
}
