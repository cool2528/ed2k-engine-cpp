#include "ed2k/metfile/known_part_met.hpp"
#include "ed2k/codec/byte_io.hpp"
namespace ed2k {
using namespace ed2k::codec;
namespace {
constexpr std::uint8_t MET_MAGIC=0x0E;
// gap 以 tag 形式编码：name "9xxxxxxx start"/"Axxxxxxx end" 简化为我们自有的 blob tag
// 为保证 round-trip，本实现把 gaps 序列化为一段 blob tag（name_id=0xF0）
void encode_entry_common(ByteWriter& w, const FileHash& h, std::span<const PartHash> parts){
  w.hash16(h);
  w.u16(std::uint16_t(parts.size()));
  for(auto& p:parts) w.hash16(p);
}
}
std::vector<std::byte> write_known_met(std::span<const KnownFileEntry> entries){
  ByteWriter w; w.u8(MET_MAGIC); w.u32(std::uint32_t(entries.size()));
  for(auto& e:entries){
    w.u32(e.date);
    encode_entry_common(w, e.hash, e.part_hashes);
    w.u32(std::uint32_t(e.tags.size()));
    write_taglist(w, e.tags);
    (void)e.size; // size 通常以 tag 携带；P1 round-trip 以 tags 为准
  }
  return w.take();
}
tl::expected<std::vector<KnownFileEntry>,std::error_code> parse_known_met(std::span<const std::byte> data){
  ByteReader r(data); std::uint8_t magic=r.u8();
  if(magic!=MET_MAGIC && magic!=0x0F) return tl::unexpected(make_error_code(errc::bad_magic));
  std::uint32_t n=r.u32(); if(n>1000000) return tl::unexpected(make_error_code(errc::count_too_large));
  std::vector<KnownFileEntry> out; out.reserve(n);
  for(std::uint32_t i=0;i<n;++i){
    KnownFileEntry e; e.date=r.u32(); e.hash=r.hash16();
    std::uint16_t pc=r.u16(); for(std::uint16_t k=0;k<pc;++k) e.part_hashes.push_back(r.hash16());
    std::uint32_t tc=r.u32(); auto tags=read_taglist(r,tc); if(!tags) return tl::unexpected(tags.error());
    e.tags=std::move(*tags);
    if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
    out.push_back(std::move(e));
  }
  return out;
}
std::vector<std::byte> write_part_met(const PartFileState& p){
  ByteWriter w; w.u8(MET_MAGIC); w.u32(0 /*date*/);
  encode_entry_common(w, p.hash, p.part_hashes);
  // gaps 序列化为一个 blob tag，保证 round-trip
  std::vector<std::byte> gapblob;
  { ByteWriter gw; gw.u32(std::uint32_t(p.gaps.size()));
    for(auto& g:p.gaps){ gw.u64(g.first); gw.u64(g.second); } gapblob=gw.take(); }
  std::vector<codec::Tag> tags=p.tags;
  { codec::Tag t; t.name_id=0xF0; t.value=gapblob; tags.push_back(t); }
  w.u32(std::uint32_t(tags.size()));
  write_taglist(w, tags);
  return w.take();
}
tl::expected<PartFileState,std::error_code> parse_part_met(std::span<const std::byte> data){
  ByteReader r(data); std::uint8_t magic=r.u8();
  if(magic!=MET_MAGIC && magic!=0x0F) return tl::unexpected(make_error_code(errc::bad_magic));
  (void)r.u32(); // date
  PartFileState p; p.hash=r.hash16();
  std::uint16_t pc=r.u16(); for(std::uint16_t k=0;k<pc;++k) p.part_hashes.push_back(r.hash16());
  std::uint32_t tc=r.u32(); auto tags=read_taglist(r,tc); if(!tags) return tl::unexpected(tags.error());
  for(auto& t:*tags){
    if(t.name_id==0xF0 && std::holds_alternative<std::vector<std::byte>>(t.value)){
      auto& blob=std::get<std::vector<std::byte>>(t.value);
      ByteReader gr(blob); std::uint32_t gc=gr.u32();
      if(gc > 1000000) return tl::unexpected(make_error_code(errc::count_too_large));
      for(std::uint32_t k=0;k<gc && gr.ok();++k){ std::uint64_t a=gr.u64(),b=gr.u64(); p.gaps.emplace_back(a,b); }
    } else p.tags.push_back(std::move(t));
  }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return p;
}
}
