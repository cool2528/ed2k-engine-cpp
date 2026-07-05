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

} // namespace ed2k::kad
