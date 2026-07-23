#pragma once
#include <chrono>
#include <cstdint>
#include <list>
#include <memory>
#include <tl/expected.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "ed2k/peer/c2c_connection.hpp"
namespace ed2k::peer {
class InboundListener {
 public:
  InboundListener(boost::asio::any_io_executor ex, std::uint16_t port = 4662);
  std::uint16_t local_port() const noexcept;
  boost::asio::awaitable<tl::expected<boost::asio::ip::tcp::socket, std::error_code>>
    accept(std::chrono::milliseconds timeout);
  // expected_ip(D1): 调用方对"即将回拨的源"的预期 IP。已知时传入, accept_peer 会把入站连接按
  // 该 IP 精确路由给对应的等待者, 而不是先到先得地分给任意一个正在等待的调用; 未知/协议层
  // 拿不到(如 eD2k GETSOURCES 对 LowID 源只给不透明 id+port, 不含真实 IP, 见 download.cpp 调用点
  // 注释)时传 std::nullopt, 退化为按登记顺序 FIFO 分派给同样未指定期望的等待者。
  boost::asio::awaitable<tl::expected<C2CConnection, std::error_code>>
    accept_peer(std::optional<UserHash> local_hash, ObfuscationPolicy policy,
                std::chrono::milliseconds timeout,
                std::shared_ptr<const infra::IPFilter> ip_filter = nullptr,
                std::uint8_t ip_filter_level = 127,
                std::optional<IPv4> expected_ip = std::nullopt);
  void close() noexcept;
 private:
  // D1: 多个 worker 可能共享同一个 InboundListener, 并发等待各自 LowID 源的回调连接。
  // Waiter 的完整定义与登记表/路由逻辑一起放在 inbound_listener.cpp(纯内部实现细节,
  // 不对外暴露); 这里前置声明即可, shared_ptr/list 均支持不完整类型作为成员。
  struct Waiter;
  boost::asio::awaitable<tl::expected<boost::asio::ip::tcp::socket, std::error_code>>
    accept_matched(std::optional<IPv4> expected_ip, std::chrono::milliseconds timeout);
  boost::asio::ip::tcp::acceptor acceptor_;
  std::list<std::shared_ptr<Waiter>> waiters_;
  bool accept_in_progress_ = false;
};
}
