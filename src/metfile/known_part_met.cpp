#include "ed2k/metfile/known_part_met.hpp"
#include "ed2k/codec/byte_io.hpp"
#include <algorithm>
#include <map>
#include <optional>
#include <string>
namespace ed2k {
using namespace ed2k::codec;
namespace {
constexpr std::uint8_t MET_MAGIC=0x0E;
constexpr std::uint8_t PARTFILE_VERSION=0xE0;
constexpr std::uint8_t PARTFILE_SPLITTEDVERSION=0xE1;
constexpr std::uint8_t PARTFILE_VERSION_LARGEFILE=0xE2;
constexpr std::uint8_t FT_FILENAME=0x01;
constexpr std::uint8_t FT_FILESIZE=0x02;
constexpr std::uint8_t FT_FILESIZE_HI=0x3A;
constexpr std::uint8_t FT_GAPSTART=0x09;
constexpr std::uint8_t FT_GAPEND=0x0A;
constexpr std::uint8_t FT_INTERNAL_GAPS=0xF0;
// E1: 私有扩展 tag(非 aMule 标准), 携带未完成 part 的块级完成位图。写在标准 aMule tag 列表内
// 的一个 Blob tag 里(数字 name_id, 与 FT_INTERNAL_GAPS 同一"私有扩展"惯例)——不认识此 tag 的
// 解析器(包括未来某个不含本字段的旧版引擎)会把它当成普通未知 tag 原样保留在 PartFileState::tags
// 里, 不影响 magic/gaps/size 等标准字段解析, 天然向后兼容。
constexpr std::uint8_t FT_INTERNAL_PARTIAL_BLOCKS=0xF1;

void encode_entry_common(ByteWriter& w, const FileHash& h, std::span<const PartHash> parts){
  w.hash16(h);
  w.u16(std::uint16_t(parts.size()));
  for(auto& p:parts) w.hash16(p);
}

std::optional<std::uint32_t> parse_gap_index(const std::string& name, std::uint8_t prefix){
  if(name.size() < 2 || static_cast<std::uint8_t>(name[0]) != prefix) return std::nullopt;
  std::uint32_t index = 0;
  for(std::size_t i=1; i<name.size(); ++i){
    unsigned char c = static_cast<unsigned char>(name[i]);
    if(c < '0' || c > '9') return std::nullopt;
    index = index * 10u + static_cast<std::uint32_t>(c - '0');
  }
  return index;
}

bool is_integer_tag(const Tag& t){
  return std::holds_alternative<std::uint64_t>(t.value);
}

std::uint64_t tag_int(const Tag& t){
  return std::get<std::uint64_t>(t.value);
}

struct GapPair {
  std::optional<std::uint64_t> start;
  std::optional<std::uint64_t> end;
};

// E1: partial_blocks 编码为单个 Blob tag(FT_INTERNAL_PARTIAL_BLOCKS), 布局:
//   u32 entry_count; 每 entry: u32 part_index, u32 block_count, ceil(block_count/8) 字节
//   (LSB-first 按位打包, 与 FILESTATUS 位图 decode_file_status 同一约定)。
// 与 FT_INTERNAL_GAPS 一样把"多条目"打包进一个 blob, 而非每条目一个 tag(gaps 用 GAPSTART_i/
// GAPEND_i 是为了兼容 aMule 自身格式; partial_blocks 是本引擎私有扩展, 无需迁就 aMule 的按索引
// 命名 tag 约定, 单 blob 更紧凑)。定义须置于 parse_amule_part_met/write_part_met 之前(两者
// 均调用本节两个函数)。
Tag encode_partial_blocks_tag(const std::vector<std::pair<std::uint32_t,std::vector<std::uint8_t>>>& partial_blocks){
  ByteWriter bw;
  bw.u32(static_cast<std::uint32_t>(partial_blocks.size()));
  for(const auto& [part_index, blocks] : partial_blocks){
    bw.u32(part_index);
    bw.u32(static_cast<std::uint32_t>(blocks.size()));
    std::vector<std::uint8_t> packed((blocks.size() + 7) / 8, 0);
    for(std::size_t i=0;i<blocks.size();++i)
      if(blocks[i]) packed[i/8] = static_cast<std::uint8_t>(packed[i/8] | (1u << (i%8)));
    for(auto byte : packed) bw.u8(byte);
  }
  Tag t; t.name_id = FT_INTERNAL_PARTIAL_BLOCKS; t.value = bw.take();
  return t;
}

// 解码失败(越界/损坏)一律返回空 vector, 与 met 整体的"陈旧/损坏则忽略, 不崩溃"防御风格一致
// ——上层 PartFile::try_load_met 对空 partial_blocks 的处理等同"该 part 无块级信息可恢复"。
std::vector<std::pair<std::uint32_t,std::vector<std::uint8_t>>> decode_partial_blocks_blob(std::span<const std::byte> blob){
  std::vector<std::pair<std::uint32_t,std::vector<std::uint8_t>>> out;
  ByteReader r(blob);
  std::uint32_t entry_count = r.u32();
  if(entry_count > 1000000) return {};
  for(std::uint32_t e=0; e<entry_count && r.ok(); ++e){
    std::uint32_t part_index = r.u32();
    std::uint32_t block_count = r.u32();
    if(block_count > 1000000) return {};
    std::size_t nbytes = (static_cast<std::size_t>(block_count) + 7) / 8;
    auto packed = r.blob(nbytes);
    if(!r.ok() || packed.size() != nbytes) return {};
    std::vector<std::uint8_t> blocks(block_count, 0);
    for(std::uint32_t i=0;i<block_count;++i){
      std::uint8_t byte = std::to_integer<std::uint8_t>(packed[i/8]);
      if(byte & (1u << (i%8))) blocks[i] = 1;
    }
    out.emplace_back(part_index, std::move(blocks));
  }
  if(!r.ok()) return {};
  return out;
}

tl::expected<PartFileState,std::error_code> parse_internal_part_met(ByteReader& r){
  (void)r.u32(); // date
  PartFileState p; p.hash=r.hash16();
  std::uint16_t pc=r.u16(); for(std::uint16_t k=0;k<pc;++k) p.part_hashes.push_back(r.hash16());
  std::uint32_t tc=r.u32(); auto tags=read_taglist(r,tc); if(!tags) return tl::unexpected(tags.error());
  for(auto& t:*tags){
    if(t.name_id==FT_INTERNAL_GAPS && std::holds_alternative<std::vector<std::byte>>(t.value)){
      auto& blob=std::get<std::vector<std::byte>>(t.value);
      ByteReader gr(blob); std::uint32_t gc=gr.u32();
      if(gc > 1000000) return tl::unexpected(make_error_code(errc::count_too_large));
      for(std::uint32_t k=0;k<gc && gr.ok();++k){ std::uint64_t a=gr.u64(),b=gr.u64(); p.gaps.emplace_back(a,b); }
      if(!gr.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
    } else p.tags.push_back(std::move(t));
  }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return p;
}

tl::expected<PartFileState,std::error_code> parse_amule_part_met(ByteReader& r){
  (void)r.u32(); // date
  PartFileState p; p.hash=r.hash16();
  std::uint16_t pc=r.u16(); for(std::uint16_t k=0;k<pc;++k) p.part_hashes.push_back(r.hash16());
  std::uint32_t tc=r.u32(); auto tags=read_taglist(r,tc); if(!tags) return tl::unexpected(tags.error());

  std::map<std::uint32_t, GapPair> gaps;
  std::optional<std::uint64_t> size_low;
  std::optional<std::uint64_t> size_high;
  for(auto& t:*tags){
    if(t.name_id == FT_FILESIZE && is_integer_tag(t)){
      size_low = tag_int(t);
      continue;
    }
    if(t.name_id == FT_FILESIZE_HI && is_integer_tag(t)){
      size_high = tag_int(t);
      continue;
    }
    if(t.name_id == FT_INTERNAL_PARTIAL_BLOCKS && std::holds_alternative<std::vector<std::byte>>(t.value)){
      p.partial_blocks = decode_partial_blocks_blob(std::get<std::vector<std::byte>>(t.value));
      continue;
    }
    if(t.has_string_name() && is_integer_tag(t)){
      if(auto idx = parse_gap_index(t.name_str, FT_GAPSTART)){
        gaps[*idx].start = tag_int(t);
        continue;
      }
      if(auto idx = parse_gap_index(t.name_str, FT_GAPEND)){
        gaps[*idx].end = tag_int(t);
        continue;
      }
    }
    p.tags.push_back(std::move(t));
  }
  if(size_low) p.size = *size_low;
  if(size_high) p.size = (*size_high << 32) | (p.size & 0xFFFFFFFFull);
  for(const auto& [idx, gap] : gaps){
    (void)idx;
    if(gap.start && gap.end && *gap.start < *gap.end) p.gaps.emplace_back(*gap.start, *gap.end);
  }
  if(!r.ok()) return tl::unexpected(make_error_code(errc::buffer_underflow));
  return p;
}

std::uint64_t file_size_for_write(const PartFileState& p){
  std::uint64_t size = p.size;
  for(const auto& [start,end] : p.gaps){
    (void)start;
    size = std::max(size, end);
  }
  return size;
}

std::string gap_name(std::uint8_t prefix, std::uint32_t index){
  std::string s(1, static_cast<char>(prefix));
  s += std::to_string(index);
  return s;
}

void write_id_int_tag(ByteWriter& w, std::uint8_t name, std::uint64_t value, bool large){
  w.u8((large ? tagtype::Uint64 : tagtype::Uint32) | tagtype::NameFlag);
  w.u8(name);
  if(large) w.u64(value);
  else w.u32(static_cast<std::uint32_t>(value));
}

void write_id_string_tag(ByteWriter& w, std::uint8_t name, const std::string& value){
  w.u8(tagtype::String | tagtype::NameFlag);
  w.u8(name);
  w.string16(value);
}

void write_named_int_tag(ByteWriter& w, const std::string& name, std::uint64_t value, bool large){
  w.u8(large ? tagtype::Uint64 : tagtype::Uint32);
  w.string16(name);
  if(large) w.u64(value);
  else w.u32(static_cast<std::uint32_t>(value));
}

bool is_part_met_generated_tag(const Tag& t){
  if(t.name_id == FT_INTERNAL_GAPS || t.name_id == FT_FILESIZE || t.name_id == FT_FILESIZE_HI
     || t.name_id == FT_INTERNAL_PARTIAL_BLOCKS) return true;
  if(t.has_string_name()){
    return parse_gap_index(t.name_str, FT_GAPSTART).has_value()
        || parse_gap_index(t.name_str, FT_GAPEND).has_value();
  }
  return false;
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
  const std::uint64_t file_size = file_size_for_write(p);
  const bool large = file_size > 0xFFFFFFFFull;
  ByteWriter w; w.u8(large ? PARTFILE_VERSION_LARGEFILE : PARTFILE_VERSION); w.u32(0 /*date*/);
  encode_entry_common(w, p.hash, p.part_hashes);

  std::vector<codec::Tag> tags;
  tags.reserve(p.tags.size());
  for(const auto& t : p.tags) if(!is_part_met_generated_tag(t)) tags.push_back(t);
  const bool has_filename = std::any_of(tags.begin(), tags.end(), [](const codec::Tag& t){
    return t.name_id == FT_FILENAME;
  });
  // E1: partial_blocks 非空时额外写一个 Blob tag(见 encode_partial_blocks_tag); 为空时不写,
  // 保持与旧格式字节级一致(现有 round-trip 测试/固定 fixture 不受影响)。
  const bool has_partial_blocks = !p.partial_blocks.empty();
  w.u32(std::uint32_t(tags.size() + (has_filename ? 0 : 1) + 1 + p.gaps.size()*2 + (has_partial_blocks ? 1 : 0)));
  write_taglist(w, tags);
  if(!has_filename) write_id_string_tag(w, FT_FILENAME, "part");
  write_id_int_tag(w, FT_FILESIZE, file_size, large);
  for(std::uint32_t i=0;i<p.gaps.size();++i){
    write_named_int_tag(w, gap_name(FT_GAPSTART, i), p.gaps[i].first, large);
    write_named_int_tag(w, gap_name(FT_GAPEND, i), p.gaps[i].second, large);
  }
  if(has_partial_blocks) write_tag(w, encode_partial_blocks_tag(p.partial_blocks));
  return w.take();
}
tl::expected<PartFileState,std::error_code> parse_part_met(std::span<const std::byte> data){
  ByteReader r(data); std::uint8_t magic=r.u8();
  if(magic==MET_MAGIC || magic==0x0F) return parse_internal_part_met(r);
  if(magic==PARTFILE_VERSION || magic==PARTFILE_SPLITTEDVERSION || magic==PARTFILE_VERSION_LARGEFILE)
    return parse_amule_part_met(r);
  return tl::unexpected(make_error_code(errc::bad_magic));
}
}
