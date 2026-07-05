#pragma once

#include <functional>
#include <span>
#include <string>
#include <system_error>

#include <tl/expected.hpp>

#include "ed2k/core/hash.hpp"
#include "ed2k/infra/friend_list.hpp"
#include "ed2k/peer/c2c_messages.hpp"

namespace ed2k::infra {

using ed2k::peer::decode_chat_message;
using ed2k::peer::encode_chat_message;

struct ChatMessage {
  UserHash sender;
  std::string text;
  bool from_friend = false;
};

class ChatRelay {
 public:
  explicit ChatRelay(const FriendList* friends = nullptr);

  std::function<void(ChatMessage)> on_message;

  tl::expected<void, std::error_code>
    on_incoming(const UserHash& sender, std::span<const std::byte> payload);

 private:
  const FriendList* friends_ = nullptr;
};

} // namespace ed2k::infra
