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

SearchExpr parse_keyword_query(const std::string& text){
  // eDonkey 关键词分隔符：空白 + 常见标点/括号(与服务器端文件名分词口径对齐)。
  static const std::string delims = " \t\n\r._-,;:()[]{}+/\\&'\"";
  std::vector<std::string> tokens;
  std::size_t i = 0;
  while(i < text.size()){
    std::size_t j = text.find_first_of(delims, i);
    if(j == std::string::npos) j = text.size();
    if(j > i) tokens.push_back(text.substr(i, j - i));
    i = j + 1;
  }
  // 无有效 token(空串或全是分隔符)：回退为整串单 Keyword，保持既有行为不抛异常。
  if(tokens.empty()) return Keyword{text};
  SearchExpr expr = Keyword{tokens[0]};
  for(std::size_t t = 1; t < tokens.size(); ++t)
    expr = std::move(expr) & SearchExpr(Keyword{tokens[t]});
  return expr;
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
