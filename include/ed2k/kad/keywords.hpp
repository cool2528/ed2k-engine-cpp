#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "ed2k/kad/kad_id.hpp"

namespace ed2k::kad {

std::vector<std::string> keywords_for_name(std::string_view text, bool allow_duplicates = false);
KadID keyword_id(std::string_view keyword);

// 多词 Kad 关键词搜索的查询计划。
// Kad 关键词索引按单词建立(每个 >=3 字符的词在其 keyword_id 对应的节点上索引文件),
// 因此整串("windows 1909")哈希做 target 会定位到无任何索引的 DHT 位置而超时。
// 正确做法:用其中一个词做 target 定位负责节点, 其余词作为本地过滤条件。
struct KadKeywordQuery {
  KadID target;                       // 定位用的 keyword_id(取查询里最长的词, 通常更 selective)
  std::vector<std::string> filters;   // 除定位词外的其余词(已小写), 供客户端本地过滤结果名
  bool valid = false;                 // 分词后无有效词(全部 <3 字符)时为 false, 调用方应回退
};

// 按 Kad 索引口径(keywords_for_name)对用户关键词分词, 选最长词做定位 target, 其余词入 filters。
KadKeywordQuery build_keyword_query(std::string_view keyword);

// 文件名(不区分大小写)是否包含 filters 里的全部词。空 filters 恒真。
bool name_contains_all(std::string_view name, const std::vector<std::string>& filters);

} // namespace ed2k::kad
