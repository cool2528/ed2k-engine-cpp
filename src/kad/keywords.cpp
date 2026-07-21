#include "ed2k/kad/keywords.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

#include "ed2k/hash/ed2k_hasher.hpp"

namespace ed2k::kad {
namespace {
constexpr std::string_view k_invalid_keyword_chars = " ()[]{}<>,._-!?:;\\/\"";

bool is_separator(char ch) noexcept {
  return k_invalid_keyword_chars.find(ch) != std::string_view::npos;
}

void lowercase_ascii(std::string& value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
}

void append_word(std::vector<std::string>& words, std::string word, bool allow_duplicates) {
  if (word.size() < 3) {
    return;
  }
  lowercase_ascii(word);
  if (!allow_duplicates) {
    words.erase(std::remove(words.begin(), words.end(), word), words.end());
  }
  words.push_back(std::move(word));
}
} // namespace

std::vector<std::string> keywords_for_name(std::string_view text, bool allow_duplicates) {
  std::vector<std::string> words;
  std::string current;
  for (char ch : text) {
    if (is_separator(ch)) {
      append_word(words, std::move(current), allow_duplicates);
      current.clear();
    } else {
      current.push_back(ch);
    }
  }
  append_word(words, std::move(current), allow_duplicates);
  return words;
}

KadID keyword_id(std::string_view keyword) {
  std::string normalized(keyword);
  lowercase_ascii(normalized);

  std::vector<std::byte> bytes;
  bytes.reserve(normalized.size());
  for (unsigned char ch : normalized) {
    bytes.push_back(std::byte{ch});
  }
  return KadID::from_bytes(hash_bytes(bytes, HashVariant::Blue).file_hash.bytes());
}

KadKeywordQuery build_keyword_query(std::string_view keyword) {
  // keywords_for_name 已按 Kad 索引口径分词: 小写、去重、丢弃 <3 字符的词。
  std::vector<std::string> words = keywords_for_name(keyword);
  KadKeywordQuery query;
  if (words.empty()) {
    return query;  // valid=false: 无有效词, 调用方回退到整串 keyword_id
  }
  // 选最长的词做定位 target(长词通常更 selective, 定位到的节点候选集更小、更可能含目标)。
  std::size_t longest = 0;
  for (std::size_t i = 1; i < words.size(); ++i) {
    if (words[i].size() > words[longest].size()) {
      longest = i;
    }
  }
  query.target = keyword_id(words[longest]);
  for (std::size_t i = 0; i < words.size(); ++i) {
    if (i != longest) {
      query.filters.push_back(words[i]);
    }
  }
  query.valid = true;
  return query;
}

bool name_contains_all(std::string_view name, const std::vector<std::string>& filters) {
  std::string lower_name(name);
  lowercase_ascii(lower_name);
  for (const auto& token : filters) {
    // filters 已在 build_keyword_query 里小写; 用子串包含而非分词匹配, 以兼容
    // 文件名里连写/不同分隔的情形(如 "consumer_editions" 命中过滤词 "editions")。
    if (lower_name.find(token) == std::string::npos) {
      return false;
    }
  }
  return true;
}

} // namespace ed2k::kad
