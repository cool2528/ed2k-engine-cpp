#pragma once
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>
#include "ed2k/core/hash.hpp"
#include "ed2k/infra/friend_list.hpp"
#include "ed2k/share/client_credits.hpp"

namespace ed2k::share {

enum class UploadQueueState {
  accepted,
  queued,
  // P2c A7: 新请求本应入队但排队队列已达 max_queued 容量上限——不插入 queued_, 由调用方(上传会话)
  // 据此答 QUEUEFULL 而非 QUEUERANKING, 让下载方放弃本源而不是傻等一个不会到来的排名。
  full
};

struct UploadQueueDecision {
  UploadQueueState state = UploadQueueState::queued;
  std::uint16_t rank = 0;
};

struct UploadQueueGrant {
  UserHash user_hash;
  FileHash file_hash;
};

// 排队队列长度不设上限的哨兵值(向后兼容旧行为: 构造时不传 max_queued 即为不限)。
inline constexpr std::size_t kUnboundedQueueLength = std::numeric_limits<std::size_t>::max();

class UploadQueue {
 public:
  explicit UploadQueue(std::size_t max_slots,
                       const ClientCredits* credits = nullptr,
                       const infra::FriendList* friends = nullptr,
                       std::size_t max_queued = kUnboundedQueueLength);

  // ip: 该请求方的来源 IP(供 P2c A8 的 UDP REASKFILEPING 应答按 (ip,file_hash) 反查 user_hash 用;
  // 已在 active_/queued_ 中的重复请求不会更新已记录的 ip)。调用方不关心该项时可省略(默认 IPv4{}),
  // 不影响原有 accepted/queued 判定逻辑。
  UploadQueueDecision enqueue(const UserHash& user_hash, const FileHash& file_hash, IPv4 ip = IPv4{});
  std::vector<UploadQueueGrant> tick();
  void release(const UserHash& user_hash);
  void remove(const UserHash& user_hash);
  bool has_slot(const UserHash& user_hash) const;
  std::uint16_t rank(const UserHash& user_hash) const;
  // 当前等待上传的排队人数
  std::size_t queued_size() const noexcept { return queued_.size(); }
  // P2c A8: 按 (ip, file_hash) 反查当前排队中的 user_hash——UDP REASKFILEPING 载荷只携带文件
  // hash, 发送方身份只能靠数据报的来源 IP 与 enqueue() 时记录的 ip 匹配(同 aMule
  // CClientList::GetClientByIP 的现实限制: 同 IP 下多个客户端排队同一文件时只能取先匹配的一个,
  // 已知的、可接受的边界情况)。未找到匹配返回 nullopt, 供调用方判定为"未知"而答 QUEUEFULL。
  std::optional<UserHash> find_queued(IPv4 ip, const FileHash& file_hash) const;

 private:
  struct Entry {
    UserHash user_hash;
    FileHash file_hash;
    IPv4 ip;
  };

  std::size_t max_slots_ = 0;
  const ClientCredits* credits_ = nullptr;
  const infra::FriendList* friends_ = nullptr;
  std::size_t max_queued_ = kUnboundedQueueLength;
  std::vector<Entry> active_;
  std::vector<Entry> queued_;
};

} // namespace ed2k::share
