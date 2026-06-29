#include "ed2k/server/search_query.hpp"
#include "ed2k/codec/byte_io.hpp"
namespace ed2k::server {
namespace {
using ed2k::codec::ByteWriter;

void serialize_into(ByteWriter& w, const SearchExpr& e);

struct Serializer {
  ByteWriter& w;
  void operator()(const Keyword& k)      { w.u8(0x01); w.string16(k.text); }
  void operator()(const TypeIs& t)       { auto s = filetype_string(t.type);
                                          w.u8(0x02); w.string16(s); w.u16(1); w.u8(tag::FT_FILETYPE); }
  void operator()(const ExtensionIs& x)  { w.u8(0x02); w.string16(x.ext); w.u16(1); w.u8(tag::FT_FILEFORMAT); }
  void operator()(const SizeAtLeast& s)  { w.u8(0x03); w.u32(static_cast<std::uint32_t>(s.bytes));
                                          w.u8(searchop::GREATER); w.u16(1); w.u8(tag::FT_FILESIZE); }
  void operator()(const SizeAtMost& s)   { w.u8(0x03); w.u32(static_cast<std::uint32_t>(s.bytes));
                                          w.u8(searchop::LESS); w.u16(1); w.u8(tag::FT_FILESIZE); }
  void operator()(const AvailAtLeast& s) { w.u8(0x03); w.u32(s.sources);
                                          w.u8(searchop::GREATER); w.u16(1); w.u8(tag::FT_SOURCES); }
  void operator()(const Box<And>& n)     { w.u8(0x00); w.u8(0x00); serialize_into(w, n->lhs); serialize_into(w, n->rhs); }
  void operator()(const Box<Or>& n)      { w.u8(0x00); w.u8(0x01); serialize_into(w, n->lhs); serialize_into(w, n->rhs); }
  void operator()(const Box<AndNot>& n)  { w.u8(0x00); w.u8(0x02); serialize_into(w, n->lhs); serialize_into(w, n->rhs); }
};

void serialize_into(ByteWriter& w, const SearchExpr& e){
  std::visit(Serializer{w}, e);
}
} // namespace

std::vector<std::byte> serialize_search(const SearchExpr& expr){
  ByteWriter w;
  serialize_into(w, expr);
  return w.take();
}

SearchExpr operator&(SearchExpr lhs, SearchExpr rhs){
  SearchExpr e; e.template emplace<Box<And>>(std::make_unique<And>(And{std::move(lhs), std::move(rhs)}));
  return e;
}
SearchExpr operator|(SearchExpr lhs, SearchExpr rhs){
  SearchExpr e; e.template emplace<Box<Or>>(std::make_unique<Or>(Or{std::move(lhs), std::move(rhs)}));
  return e;
}
SearchExpr and_not(SearchExpr lhs, SearchExpr rhs){
  SearchExpr e; e.template emplace<Box<AndNot>>(std::make_unique<AndNot>(AndNot{std::move(lhs), std::move(rhs)}));
  return e;
}
}
