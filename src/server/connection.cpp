#include "ed2k/server/connection.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/util/error.hpp"
#include <chrono>
#include <span>
namespace ed2k::server {
namespace asio = boost::asio;
using clock_type = std::chrono::steady_clock;

ServerConnection::ServerConnection(asio::any_io_executor ex) : conn_(ex) {}
void ServerConnection::on_event(std::function<void(const ServerEvent&)> sink){ on_event_ = std::move(sink); }
void ServerConnection::set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level) {
  conn_.set_ip_filter(std::move(filter), level);
}
void ServerConnection::close() noexcept { conn_.close(); }
bool ServerConnection::is_open() const noexcept { return conn_.is_open(); }

void ServerConnection::dispatch_push(const net::Packet& pkt){
  if(!on_event_) return;
  std::span<const std::byte> p{pkt.payload};
  switch(pkt.opcode){
    case op::SERVERMESSAGE: { auto d=decode_server_message(p); if(d) on_event_(ServerMessageEvent{std::move(*d)}); break; }
    case op::SERVERSTATUS:  { auto d=decode_server_status(p);  if(d) on_event_(ServerStatusEvent{d->users,d->files}); break; }
    case op::SERVERIDENT:   { auto d=decode_server_ident(p);   if(d) on_event_(ServerIdentEvent{d->hash,d->ip,d->port,d->name,d->description}); break; }
    case op::SERVERLIST:    { auto d=decode_server_list(p);    if(d) on_event_(ServerListEvent{std::move(*d)}); break; }
    case op::CALLBACKREQUESTED: { auto d=decode_callback_requested(p); if(d) on_event_(CallbackRequestedEvent{d->ip,d->port}); break; }
    default: break;
  }
}

asio::awaitable<tl::expected<net::Packet,std::error_code>>
ServerConnection::pump_until(std::uint8_t want, std::chrono::milliseconds budget){
  auto deadline = clock_type::now() + budget;
  while(true){
    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
    if(rem.count() <= 0) co_return tl::unexpected(make_error_code(errc::timed_out));
    auto rp = co_await conn_.recv(rem);
    if(!rp) co_return tl::unexpected(rp.error());
    auto& pkt = *rp;
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
  auto cr = co_await conn_.connect(ip, port, timeout);
  if(!cr) co_return tl::unexpected(cr.error());
  net::Packet req; req.protocol = net::proto::eDonkey; req.opcode = op::LOGINREQUEST; req.payload = encode_login(p);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::IDCHANGE, timeout);
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
  auto cr = co_await conn_.connect_via_proxy(proxy, ip, port, timeout);
  if(!cr) co_return tl::unexpected(cr.error());
  net::Packet req; req.protocol = net::proto::eDonkey; req.opcode = op::LOGINREQUEST; req.payload = encode_login(p);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::IDCHANGE, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  auto ic = decode_id_change(rp->payload);
  if(!ic) co_return tl::unexpected(ic.error());
  LoginResult lr; lr.client_id = ic->id; lr.flags = ic->flags; lr.high_id = ic->high_id();
  co_return lr;
}

asio::awaitable<tl::expected<std::vector<SearchResultItem>,std::error_code>>
ServerConnection::search(const SearchExpr& expr, std::chrono::milliseconds timeout){
  net::Packet req; req.protocol = net::proto::eDonkey; req.opcode = op::SEARCHREQUEST; req.payload = encode_search(expr);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::SEARCHRESULT, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_search_result(rp->payload);
}

asio::awaitable<tl::expected<FoundSources,std::error_code>>
ServerConnection::get_sources(const FileHash& h, std::uint64_t size, std::chrono::milliseconds timeout){
  net::Packet req; req.protocol = net::proto::eDonkey; req.opcode = op::GETSOURCES; req.payload = encode_get_sources(h, size);
  auto sr = co_await conn_.send(req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(op::FOUNDSOURCES, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_found_sources(rp->payload);
}
asio::awaitable<tl::expected<void,std::error_code>>
ServerConnection::callback_request(std::uint32_t client_id, std::chrono::milliseconds timeout){
  (void)timeout;
  net::Packet req; req.protocol = net::proto::eDonkey; req.opcode = op::CALLBACKREQUEST;
  req.payload = encode_callback_request(client_id);
  co_return co_await conn_.send(req);
}

asio::awaitable<tl::expected<void,std::error_code>>
ServerConnection::publish_files(std::span<const ed2k::share::KnownFile> files){
  net::Packet req; req.protocol = net::proto::eDonkey; req.opcode = op::OFFERFILES;
  req.payload = encode_offer_files(files);
  co_return co_await conn_.send(req);
}

asio::awaitable<tl::expected<void,std::error_code>>
ServerConnection::receive_events(std::chrono::milliseconds timeout){
  auto rp = co_await pump_until(op::NONE, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return tl::expected<void,std::error_code>{};
}
}
