#include "ed2k/peer/inbound_listener.hpp"
#include "ed2k/util/error.hpp"
#include "ed2k/net/encrypted_stream_socket.hpp"
#include "ed2k/net/packet.hpp"
#include <algorithm>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/experimental/channel.hpp>
namespace ed2k::peer {
namespace asio = boost::asio; using tcp = asio::ip::tcp;
using clock_type = std::chrono::steady_clock;
namespace {
std::optional<std::chrono::milliseconds> remaining(clock_type::time_point deadline) {
  auto value = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
  if (value.count() <= 0) return std::nullopt;
  return value;
}
// D1: 非 accepter 角色轮询自身信号量的切片间隔。单 io_context 下不能用 condition_variable
// 阻塞唯一网络线程(同 download.cpp cancellable_wait 的既有约束), 改用短切片轮询——一旦当前
// accepter 让位(accept_in_progress_ 变 false)就能在至多一个切片内接棒去争取下一条连接。
inline constexpr std::chrono::milliseconds kAcceptPollSlice{20};
}

// D1(入站 LowID 回调连接的身份路由): 一个 InboundListener 内部完整的等待者记录。修复前
// accept_peer 直接对共享 acceptor_ 发起各自独立的 async_accept——同一文件的多个 worker(各自
// 对应一个 LowID 源, 先发 OP_CALLBACKREQUEST 再等对端回拨)并发调用时, 哪个连接分给哪次调用
// 完全取决于 asio 内部 async_accept 的就绪顺序, 与"连接实际来自哪个源"无关(源端各自的网络延迟
// 互相独立), 于是 worker A 可能拿到源 B 回拨的连接、B 则一直等不到连接直至超时。
struct InboundListener::Waiter {
  std::optional<IPv4> expected_ip;
  std::shared_ptr<asio::experimental::channel<void(boost::system::error_code)>> ready;
  tl::expected<tcp::socket, std::error_code> result;
  // 显式构造函数: result 的类型 tl::expected<tcp::socket,...> 没有默认构造(tcp::socket 本身
  // 不可默认构造, 总需要一个 executor), 聚合/隐式默认构造会被删除, 故这里显式给 result 一个
  // 占位错误值(超时), accepter 命中匹配时会整体覆盖为真正的 socket。
  explicit Waiter(std::optional<IPv4> ip, decltype(ready) ch)
    : expected_ip(ip), ready(std::move(ch)), result(tl::unexpected(make_error_code(errc::timed_out))) {}
};

InboundListener::InboundListener(asio::any_io_executor ex, std::uint16_t port)
  : acceptor_(ex, tcp::endpoint(asio::ip::address_v4::any(), port)) {
  acceptor_.set_option(asio::socket_base::reuse_address(true));
}
std::uint16_t InboundListener::local_port() const noexcept {
  boost::system::error_code ig; return acceptor_.local_endpoint(ig).port();
}
asio::awaitable<tl::expected<tcp::socket, std::error_code>>
InboundListener::accept(std::chrono::milliseconds timeout){
  auto [ec, sock] = co_await acceptor_.async_accept(
    asio::cancel_after(timeout, asio::as_tuple(asio::use_awaitable)));
  if(ec){
    if(ec == asio::error::operation_aborted) co_return tl::unexpected(make_error_code(errc::timed_out));
    co_return tl::unexpected(make_error_code(errc::connection_closed));
  }
  co_return std::move(sock);
}

// 修复: 引入等待登记表 waiters_ + 单读者 accept 广播——任意时刻至多一个协程持有"读 acceptor_"
// 的职责(accept_in_progress_ 充当互斥标记; 单线程 io_context 下协程只在 co_await 处让出,
// 赋值/查表本身不需要锁)。持有该职责的协程循环 accept 原始连接, 每接到一条就按 remote IP 在
// waiters_ 中精确匹配"期望该 IP"的等待者优先投递; 找不到精确匹配时退化为最早登记的"未指定
// 期望"(expected_ip==nullopt)等待者(FIFO, 兼容未提供期望 IP 的调用方——比如当前 eD2k 协议下
// download.cpp 对 LowID 源本就拿不到真实 IP, 见该调用点注释)。两者都没有则该连接无人认领,
// 直接关闭丢弃(不会抢占已有明确期望、正在等别的源的等待者)。非 accepter 角色完全不触碰
// acceptor_, 只切片轮询自己的信号量, 一旦当前 accepter 让位就有机会在下一切片内接棒。
asio::awaitable<tl::expected<tcp::socket, std::error_code>>
InboundListener::accept_matched(std::optional<IPv4> expected_ip, std::chrono::milliseconds timeout) {
  const auto deadline = clock_type::now() + timeout;
  auto ready_ch = std::make_shared<asio::experimental::channel<void(boost::system::error_code)>>(
      acceptor_.get_executor(), 1);
  auto self = std::make_shared<Waiter>(expected_ip, std::move(ready_ch));
  waiters_.push_back(self);
  bool fulfilled = false;   // 一旦被某次 accepter 分派命中就置真; 用于收尾时判断是否需要自摘登记表

  auto forget_self = [&]() {
    if (fulfilled) return;
    auto pos = std::find(waiters_.begin(), waiters_.end(), self);
    if (pos != waiters_.end()) waiters_.erase(pos);
  };

  while (true) {
    auto budget = remaining(deadline);
    if (!budget) { forget_self(); co_return tl::unexpected(make_error_code(errc::timed_out)); }

    if (!accept_in_progress_) {
      // 本协程临时担任 accepter: 循环收原始连接直至命中自己的等待条目, 或出错/超时。
      accept_in_progress_ = true;
      std::error_code accepter_err;
      bool accepter_failed = false;
      while (true) {
        auto inner_budget = remaining(deadline);
        if (!inner_budget) { accepter_err = make_error_code(errc::timed_out); accepter_failed = true; break; }
        auto [ec, sock] = co_await acceptor_.async_accept(
            asio::cancel_after(*inner_budget, asio::as_tuple(asio::use_awaitable)));
        if (ec) {
          accepter_err = (ec == asio::error::operation_aborted) ? make_error_code(errc::timed_out)
                                                                  : make_error_code(errc::connection_closed);
          accepter_failed = true;
          break;
        }
        boost::system::error_code remote_ec;
        auto remote_endpoint = sock.remote_endpoint(remote_ec);
        std::optional<IPv4> remote_ip;
        if (!remote_ec && remote_endpoint.address().is_v4())
          remote_ip = IPv4::from_host(remote_endpoint.address().to_v4().to_uint());

        auto target = waiters_.end();
        if (remote_ip) {
          for (auto it = waiters_.begin(); it != waiters_.end(); ++it) {
            if ((*it)->expected_ip && *(*it)->expected_ip == *remote_ip) { target = it; break; }
          }
        }
        if (target == waiters_.end()) {
          for (auto it = waiters_.begin(); it != waiters_.end(); ++it) {
            if (!(*it)->expected_ip) { target = it; break; }
          }
        }
        if (target == waiters_.end()) { sock.close(); continue; }   // 无人认领: 丢弃, 不抢占他人

        auto matched = *target;
        waiters_.erase(target);
        matched->result = std::move(sock);
        matched->ready->try_send(boost::system::error_code{});
        if (matched == self) break;   // 命中自己: 结束 accepter 循环, 下面统一走取值路径
        // 命中的是别的等待者: 自己仍是 accepter, 继续循环争取下一条连接
      }
      accept_in_progress_ = false;
      if (accepter_failed) { forget_self(); co_return tl::unexpected(accepter_err); }
      fulfilled = true;
      co_return std::move(self->result);
    }

    // 非 accepter: 短切片轮询自己的信号量, 一旦当前 accepter 让位就有机会在下一轮接棒。
    auto slice = std::min(kAcceptPollSlice, *budget);
    auto [ec] = co_await self->ready->async_receive(
        asio::cancel_after(slice, asio::as_tuple(asio::use_awaitable)));
    if (!ec) { fulfilled = true; co_return std::move(self->result); }
    // 切片超时(operation_aborted)且尚未被投递: 回外层循环重新判断是否轮到自己当 accepter,
    // 或整体预算已耗尽。
  }
}

asio::awaitable<tl::expected<C2CConnection, std::error_code>>
InboundListener::accept_peer(std::optional<UserHash> local_hash,
                             ObfuscationPolicy policy,
                             std::chrono::milliseconds timeout,
                             std::shared_ptr<const infra::IPFilter> ip_filter,
                             std::uint8_t ip_filter_level,
                             std::optional<IPv4> expected_ip) {
  const auto deadline = clock_type::now() + timeout;
  auto budget = remaining(deadline);
  if (!budget) co_return tl::unexpected(make_error_code(errc::timed_out));
  auto accepted = co_await accept_matched(expected_ip, *budget);
  if (!accepted) co_return tl::unexpected(accepted.error());
  auto socket = std::move(*accepted);

  boost::system::error_code remote_ec;
  auto remote_endpoint = socket.remote_endpoint(remote_ec);
  std::optional<IPv4> remote;
  if (!remote_ec && remote_endpoint.address().is_v4()) {
    remote = IPv4::from_host(remote_endpoint.address().to_v4().to_uint());
    if (ip_filter && ip_filter->blocked(*remote, ip_filter_level)) {
      socket.close();
      co_return tl::unexpected(make_error_code(errc::ip_filtered));
    }
  }

  std::byte first{};
  budget = remaining(deadline);
  if (!budget) {
    socket.close();
    co_return tl::unexpected(make_error_code(errc::timed_out));
  }
  auto [peek_ec, count] = co_await socket.async_receive(
      asio::buffer(&first, 1), tcp::socket::message_peek,
      asio::cancel_after(*budget, asio::as_tuple(asio::use_awaitable)));
  if (peek_ec || count != 1) {
    socket.close();
    if (peek_ec == asio::error::operation_aborted)
      co_return tl::unexpected(make_error_code(errc::timed_out));
    co_return tl::unexpected(make_error_code(errc::connection_closed));
  }

  const auto marker = std::to_integer<std::uint8_t>(first);
  const bool plain = marker == net::proto::eDonkey || marker == net::proto::eMule ||
                     marker == net::proto::zlib;
  if (plain) {
    if (policy == ObfuscationPolicy::required) {
      socket.close();
      co_return tl::unexpected(make_error_code(errc::server_protocol_error));
    }
    co_return C2CConnection(std::move(socket));
  }

  if (policy == ObfuscationPolicy::disabled || !local_hash) {
    socket.close();
    co_return tl::unexpected(make_error_code(errc::server_protocol_error));
  }
  net::EncryptedStreamSocket encrypted(std::move(socket));
  budget = remaining(deadline);
  if (!budget) co_return tl::unexpected(make_error_code(errc::timed_out));
  auto negotiated = co_await encrypted.handshake_acceptor(*local_hash, *budget);
  if (!negotiated) co_return tl::unexpected(negotiated.error());
  co_return C2CConnection(std::move(encrypted), std::move(remote));
}
void InboundListener::close() noexcept { boost::system::error_code ig; acceptor_.close(ig); }
}
