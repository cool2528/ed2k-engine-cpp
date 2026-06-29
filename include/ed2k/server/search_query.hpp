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
struct TypeIs       { FileType type = FileType::Any; };          // FT_FILETYPE 字符串元
struct ExtensionIs  { std::string ext; };                        // FT_FILEFORMAT 字符串元
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

SearchExpr operator&(SearchExpr lhs, SearchExpr rhs);
SearchExpr operator|(SearchExpr lhs, SearchExpr rhs);
SearchExpr and_not(SearchExpr lhs, SearchExpr rhs);
}
