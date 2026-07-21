#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <variant>
#include <vector>
#include <cstddef>
#include "ed2k/server/opcodes.hpp"
namespace ed2k::server {

struct Keyword      { std::string text; };
struct TypeIs       { FileType type = FileType::Any; };          // FT_FILETYPE string meta
struct ExtensionIs  { std::string ext; };                        // FT_FILEFORMAT string meta
struct SizeAtLeast  { std::uint64_t bytes = 0; };                // FT_FILESIZE, GREATER
struct SizeAtMost   { std::uint64_t bytes = 0; };                // FT_FILESIZE, LESS
struct AvailAtLeast { std::uint32_t sources = 0; };              // FT_SOURCES, GREATER

struct And; struct Or; struct AndNot;
template <class T> using Box = std::unique_ptr<T>;
using SearchExpr = std::variant<Keyword, TypeIs, ExtensionIs, SizeAtLeast, SizeAtMost, AvailAtLeast,
                                Box<And>, Box<Or>, Box<AndNot>>;
struct And    { SearchExpr lhs, rhs; };
struct Or     { SearchExpr lhs, rhs; };
struct AndNot { SearchExpr lhs, rhs; };   // lhs AND NOT rhs

std::vector<std::byte> serialize_search(const SearchExpr& expr);

// 把用户输入的关键词串按 eDonkey 惯用分隔符(空白/._-,;: 括号等)分词，
// 多个 token 用 AND 组合返回。eDonkey 服务器按 token 精确匹配文件名分词结果，
// 整串作单个 Keyword 时("windows 10"/"windows_10")无法命中任何文件名的单一 token，
// 必须拆成 Keyword("windows") AND Keyword("10")。无有效 token 时回退为整串单 Keyword。
SearchExpr parse_keyword_query(const std::string& text);

SearchExpr operator&(SearchExpr lhs, SearchExpr rhs);
SearchExpr operator|(SearchExpr lhs, SearchExpr rhs);
SearchExpr and_not(SearchExpr lhs, SearchExpr rhs);
}
