#pragma once
#include <cstdint>
#include <string>
#include <variant>
#include <vector>
#include <span>
#include <tl/expected.hpp>
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/util/error.hpp"
namespace ed2k::codec {
namespace tagtype {
constexpr std::uint8_t Hash16=0x01, String=0x02, Uint32=0x03, Blob=0x07, Uint16=0x08, Uint8=0x09;
constexpr std::uint8_t NameFlag=0x80;
}
struct Tag {
  std::uint8_t name_id=0;
  std::string  name_str;
  std::variant<std::uint64_t,std::string,MD4Hash,std::vector<std::byte>> value;
  bool has_string_name() const { return name_id==0 && !name_str.empty(); }
};
void write_tag(ByteWriter&, const Tag&);
tl::expected<Tag,std::error_code> read_tag(ByteReader&);
void write_taglist(ByteWriter&, std::span<const Tag>);
tl::expected<std::vector<Tag>,std::error_code> read_taglist(ByteReader&, std::uint32_t count);
}
