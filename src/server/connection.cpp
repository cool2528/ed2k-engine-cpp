#include "ed2k/server/connection.hpp"
#include "ed2k/net/connection.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/util/error.hpp"
#include <chrono>
#include <map>
#include <span>
#include <utility>
#include <vector>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/use_awaitable.hpp>
namespace ed2k::server {
namespace asio = boost::asio;
using clock_type = std::chrono::steady_clock;

struct ServerConnection::SubscriptionState {
  std::map<std::size_t, std::function<void(const ServerEvent&)>> sinks;
  std::size_t next_id = 1;
};

struct ServerConnection::Impl {
  explicit Impl(asio::any_io_executor ex) : conn(ex), observers(std::make_shared<SubscriptionState>()) {}

  // 单一物理读者协调: search/get_sources/get_server_list/receive_events 等方法都最终经
  // pump_until 调用 conn.recv()——但 conn 是常驻的 receive_loop(Session 层)与这些前台请求
  // 共用的同一条连接, 而 asio 不允许对同一 socket 并发发起读操作(否则一帧数据会被两个挂起的
  // 读操作错误切分, 双方都收不到完整帧从而各自超时)。
  // 修复方式: 任意时刻只允许一个协程真正调用 conn.recv()('owner'), 其余调用方降级为
  // 'waiter'——按自己关心的 opcode 注册一个 channel 后挂起等待; owner 收到帧后若发现有
  // waiter 正等待该 opcode, 直接转投而不是按原逻辑丢弃/处理, 从而在不改变单调用方行为的前提下
  // 让并发调用安全共享同一条连接。
  using WaitCh = asio::experimental::channel<void(boost::system::error_code, net::Packet)>;
  bool pumping = false;
  std::multimap<std::uint8_t, std::shared_ptr<WaitCh>> waiters;

  void dispatch_push(const net::Packet& pkt);
  asio::awaitable<tl::expected<net::Packet,std::error_code>>
    pump_until(std::uint8_t want, std::chrono::milliseconds budget);
  // 从 waiters 中移除指定的等待者条目(按值匹配, 而非按 opcode 匹配到第一个即删), 用于等待者
  // 超时后自行清理注册、以及 owner 转投后的防御性二次清理(幂等)。
  void erase_waiter(std::uint8_t opcode, const std::shared_ptr<WaitCh>& ch){
    auto [first, last] = waiters.equal_range(opcode);
    for(auto it = first; it != last; ++it){
      if(it->second == ch){ waiters.erase(it); return; }
    }
  }

  net::Connection conn;
  std::shared_ptr<SubscriptionState> observers;
};

ServerConnection::Subscription::Subscription(std::weak_ptr<SubscriptionState> state, std::size_t id) noexcept
  : state_(std::move(state)), id_(id) {}
ServerConnection::Subscription::~Subscription() { reset(); }
ServerConnection::Subscription::Subscription(Subscription&& other) noexcept
  : state_(std::move(other.state_)), id_(std::exchange(other.id_, 0)) {}
ServerConnection::Subscription& ServerConnection::Subscription::operator=(Subscription&& other) noexcept {
  if(this != &other){
    reset();
    state_ = std::move(other.state_);
    id_ = std::exchange(other.id_, 0);
  }
  return *this;
}
void ServerConnection::Subscription::reset() noexcept {
  if(id_ == 0) return;
  if(auto state = state_.lock()) state->sinks.erase(id_);
  id_ = 0;
}

ServerConnection::ServerConnection(asio::any_io_executor ex) : impl_(std::make_unique<Impl>(ex)) {}
ServerConnection::~ServerConnection() = default;
ServerConnection::ServerConnection(ServerConnection&&) noexcept = default;
ServerConnection& ServerConnection::operator=(ServerConnection&&) noexcept = default;

ServerConnection::Subscription ServerConnection::on_event(std::function<void(const ServerEvent&)> sink){
  const auto id = impl_->observers->next_id++;
  impl_->observers->sinks.emplace(id, std::move(sink));
  return Subscription{impl_->observers, id};
}
void ServerConnection::set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level) {
  impl_->conn.set_ip_filter(std::move(filter), level);
}
void ServerConnection::close() noexcept { impl_->conn.close(); }
bool ServerConnection::is_open() const noexcept { return impl_->conn.is_open(); }

void ServerConnection::Impl::dispatch_push(const net::Packet& pkt){
  if(observers->sinks.empty()) return;
  auto dispatch = [&](ServerEvent event) {
    std::vector<std::function<void(const ServerEvent&)>> sinks;
    sinks.reserve(observers->sinks.size());
    for(auto& [id, sink] : observers->sinks) sinks.push_back(sink);
    for(auto& sink : sinks) sink(event);
  };
  std::span<const std::byte> p{pkt.payload};
  switch(pkt.opcode){
    case op::SERVERMESSAGE: { auto d=decode_server_message(p); if(d) dispatch(ServerMessageEvent{std::move(*d)}); break; }
    case op::SERVERSTATUS:  { auto d=decode_server_status(p);  if(d) dispatch(ServerStatusEvent{d->users,d->files}); break; }
    case op::SERVERIDENT:   { auto d=decode_server_ident(p);   if(d) dispatch(ServerIdentEvent{d->hash,d->ip,d->port,d->name,d->description}); break; }
    case op::SERVERLIST:    { auto d=decode_server_list(p);    if(d) dispatch(ServerListEvent{std::move(*d)}); break; }
    case op::CALLBACKREQUESTED: { auto d=decode_callback_requested(p); if(d) dispatch(CallbackRequestedEvent{d->ip,d->port}); break; }
    default: break;
  }
}

asio::awaitable<tl::expected<net::Packet,std::error_code>>
ServerConnection::Impl::pump_until(std::uint8_t want, std::chrono::milliseconds budget){
  auto deadline = clock_type::now() + budget;
  if(pumping){
    // 等待者路径: 已有协程(通常是 Session 的常驻 receive_loop)持有物理读权, 本次不直接碰
    // socket, 只注册关注的 opcode 并挂起, 由 owner 收到匹配帧后转投; 超时按自己的 budget 计。
    auto ch = std::make_shared<WaitCh>(conn.executor(), 1);
    waiters.emplace(want, ch);
    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
    if(rem.count() <= 0){
      erase_waiter(want, ch);
      co_return tl::unexpected(make_error_code(errc::timed_out));
    }
    auto [ec, pkt] = co_await ch->async_receive(asio::cancel_after(rem, asio::as_tuple(asio::use_awaitable)));
    erase_waiter(want, ch);   // 已被投递时是幂等的空操作; 未投递(超时)时在此兜底清理注册
    if(ec) co_return tl::unexpected(make_error_code(errc::timed_out));
    co_return pkt;
  }
  pumping = true;
  struct PumpGuard { bool& flag; ~PumpGuard(){ flag = false; } } guard{pumping};
  while(true){
    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
    if(rem.count() <= 0) co_return tl::unexpected(make_error_code(errc::timed_out));
    auto rp = co_await conn.recv(rem);
    if(!rp) co_return tl::unexpected(rp.error());
    auto& pkt = *rp;
    // 有等待者正在关心此 opcode: 转投给它, 而不是按下面的默认规则处理/丢弃。
    if(auto it = waiters.find(pkt.opcode); it != waiters.end()){
      auto ch = it->second;
      waiters.erase(it);
      ch->try_send(boost::system::error_code{}, pkt);
      if(pkt.opcode == want) co_return pkt;   // 本次调用恰好也在等同一 opcode, 一并返回
      continue;
    }
    if(pkt.opcode == want) co_return pkt;
    if(pkt.opcode == op::REJECT) co_return tl::unexpected(make_error_code(errc::login_rejected));
    bool is_push = (pkt.opcode==op::SERVERMESSAGE||pkt.opcode==op::SERVERSTATUS||pkt.opcode==op::SERVERIDENT
                    ||pkt.opcode==op::SERVERLIST||pkt.opcode==op::CALLBACKREQUESTED);
    if(is_push){
      dispatch_push(pkt);
      if(want == op::NONE) co_return pkt;        // receive_events：收一个推送即返回
      continue;
    }
    // 未知/非预期响应类 opcode：记录并跳过（继续泵）
    continue;
  }
}

asio::awaitable<tl::expected<LoginResult,std::error_code>>
ServerConnection::connect_and_login(IPv4 ip, std::uint16_t port, const LoginParams& p, std::chrono::milliseconds timeout){
  auto cr = co_await impl_->conn.connect(ip, port, timeout);
  if(!cr) co_return tl::unexpected(cr.error());
  net::Packet req; req.protocol = net::proto::eDonkey; req.opcode = op::LOGINREQUEST; req.payload = encode_login(p);
  auto sr = co_await impl_->conn.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await impl_->pump_until(op::IDCHANGE, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  auto ic = decode_id_change(rp->payload);
  if(!ic) co_return tl::unexpected(ic.error());
  LoginResult lr; lr.client_id = ic->id; lr.flags = ic->flags; lr.high_id = ic->high_id();
  co_return lr;
}

asio::awaitable<tl::expected<LoginResult,std::error_code>>
ServerConnection::connect_and_login_via_proxy(const infra::ProxyConfig& proxy,
                                              IPv4 ip,
                                              std::uint16_t port,
                                              const LoginParams& p,
                                              std::chrono::milliseconds timeout){
  auto cr = co_await impl_->conn.connect_via_proxy(proxy, ip, port, timeout);
  if(!cr) co_return tl::unexpected(cr.error());
  net::Packet req; req.protocol = net::proto::eDonkey; req.opcode = op::LOGINREQUEST; req.payload = encode_login(p);
  auto sr = co_await impl_->conn.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await impl_->pump_until(op::IDCHANGE, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  auto ic = decode_id_change(rp->payload);
  if(!ic) co_return tl::unexpected(ic.error());
  LoginResult lr; lr.client_id = ic->id; lr.flags = ic->flags; lr.high_id = ic->high_id();
  co_return lr;
}

asio::awaitable<tl::expected<std::vector<SearchResultItem>,std::error_code>>
ServerConnection::search(const SearchExpr& expr, std::chrono::milliseconds timeout){
  net::Packet req; req.protocol = net::proto::eDonkey; req.opcode = op::SEARCHREQUEST; req.payload = encode_search(expr);
  auto sr = co_await impl_->conn.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await impl_->pump_until(op::SEARCHRESULT, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_search_result(rp->payload);
}

asio::awaitable<tl::expected<FoundSources,std::error_code>>
ServerConnection::get_sources(const FileHash& h, std::uint64_t size, std::chrono::milliseconds timeout){
  net::Packet req; req.protocol = net::proto::eDonkey; req.opcode = op::GETSOURCES; req.payload = encode_get_sources(h, size);
  auto sr = co_await impl_->conn.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await impl_->pump_until(op::FOUNDSOURCES, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_found_sources(rp->payload);
}
asio::awaitable<tl::expected<std::vector<std::pair<IPv4,std::uint16_t>>,std::error_code>>
ServerConnection::get_server_list(std::chrono::milliseconds timeout){
  net::Packet req; req.protocol = net::proto::eDonkey; req.opcode = op::GETSERVERLIST; req.payload = encode_get_server_list();
  auto sr = co_await impl_->conn.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await impl_->pump_until(op::SERVERLIST, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_server_list(rp->payload);
}
asio::awaitable<tl::expected<void,std::error_code>>
ServerConnection::callback_request(std::uint32_t client_id, std::chrono::milliseconds timeout){
  (void)timeout;
  net::Packet req; req.protocol = net::proto::eDonkey; req.opcode = op::CALLBACKREQUEST;
  req.payload = encode_callback_request(client_id);
  co_return co_await impl_->conn.send(req);
}

asio::awaitable<tl::expected<void,std::error_code>>
ServerConnection::publish_files(std::span<const ed2k::share::KnownFile> files){
  net::Packet req; req.protocol = net::proto::eDonkey; req.opcode = op::OFFERFILES;
  req.payload = encode_offer_files(files);
  co_return co_await impl_->conn.send(req);
}

asio::awaitable<tl::expected<void,std::error_code>>
ServerConnection::receive_events(std::chrono::milliseconds timeout){
  auto rp = co_await impl_->pump_until(op::NONE, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return tl::expected<void,std::error_code>{};
}
}
