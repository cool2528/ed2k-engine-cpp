#include "ed2k/infra/chat_relay.hpp"

namespace ed2k::infra {

ChatRelay::ChatRelay(const FriendList* friends) : friends_(friends) {}

tl::expected<void, std::error_code>
ChatRelay::on_incoming(const UserHash& sender, std::span<const std::byte> payload) {
  auto decoded = ed2k::peer::decode_chat_message(payload);
  if (!decoded) {
    return tl::unexpected(decoded.error());
  }
  if (on_message) {
    ChatMessage message;
    message.sender = sender;
    message.text = std::move(*decoded);
    message.from_friend = friends_ && friends_->contains(sender);
    on_message(std::move(message));
  }
  return {};
}

} // namespace ed2k::infra
