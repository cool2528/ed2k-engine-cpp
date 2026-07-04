#include "ed2k/server/udp_connection.hpp"
#include "ed2k/util/error.hpp"
#include <chrono>
namespace ed2k::server {
namespace asio = boost::asio;
using udp = asio::ip::udp;
using clock_type = std::chrono::steady_clock;

UdpServerConnection::UdpServerConnection(asio::any_io_executor ex, IPv4 ip, std::uint16_t port)
  : sock_(ex), server_(udp::endpoint(asio::ip::address_v4(ip.host()), port)) {}
void UdpServerConnection::on_event(std::function<void(const UdpEvent&)> sink){ on_event_ = std::move(sink); }
void UdpServerConnection::close() noexcept { sock_.close(); }

asio::awaitable<tl::expected<ed2k::net::Packet,std::error_code>>
UdpServerConnection::pump_until(std::uint8_t want, std::chrono::milliseconds budget){
  auto deadline = clock_type::now() + budget;
  while(true){
    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
    if(rem.count() <= 0) co_return tl::unexpected(make_error_code(errc::timed_out));
    auto rp = co_await sock_.recv_from(rem);
    if(!rp) co_return tl::unexpected(rp.error());
    auto [pkt, sender] = std::move(*rp);
    if(sender != server_) continue;              // 过滤非目标源
    if(pkt.opcode == want) co_return std::move(pkt);
    if(pkt.opcode == udpop::INVALID_LOWID){
      if(on_event_){
        auto id = decode_invalid_low_id(pkt.payload);
        if(id) on_event_(InvalidLowIdEvent{*id});
      }
      continue;
    }
    continue;                                     // 未知 opcode 跳过
  }
}
asio::awaitable<tl::expected<UdpSearchResult,std::error_code>>
UdpServerConnection::global_search(const SearchExpr& expr, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=udpop::GLOBSEARCHREQ2;
  req.payload = encode_glob_search_req(expr);
  auto sr = co_await sock_.send_to(server_, req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(udpop::GLOBSEARCHRES, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_glob_search_res(rp->payload);
}
asio::awaitable<tl::expected<FoundSources,std::error_code>>
UdpServerConnection::get_sources(const FileHash& h, std::uint64_t size, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=udpop::GLOBGETSOURCES2;
  req.payload = encode_get_sources_req(h, size);
  auto sr = co_await sock_.send_to(server_, req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(udpop::GLOBFOUNDSOURCES, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  auto v = decode_glob_found_sources(rp->payload);
  if(!v) co_return tl::unexpected(v.error());
  for(auto& fs : *v) if(fs.hash == h) co_return std::move(fs);
  co_return FoundSources{h, {}};
}
asio::awaitable<tl::expected<ServerStat,std::error_code>>
UdpServerConnection::server_status(std::uint32_t challenge, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=udpop::GLOBSERVSTATREQ;
  req.payload = encode_server_status_req(challenge);
  auto sr = co_await sock_.send_to(server_, req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(udpop::GLOBSERVSTATRES, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_server_stat(rp->payload, challenge);
}
asio::awaitable<tl::expected<std::vector<std::pair<IPv4,std::uint16_t>>,std::error_code>>
UdpServerConnection::server_list(IPv4 ask_ip, std::uint16_t ask_port, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=udpop::SERVER_LIST_REQ;
  req.payload = encode_server_list_req(ask_ip, ask_port);
  auto sr = co_await sock_.send_to(server_, req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(udpop::SERVER_LIST_RES, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_server_list(rp->payload);
}
asio::awaitable<tl::expected<ServerDesc,std::error_code>>
UdpServerConnection::server_desc(std::uint32_t challenge, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=udpop::SERVER_DESC_REQ;
  req.payload = encode_server_desc_req(challenge);
  auto sr = co_await sock_.send_to(server_, req);
  if(!sr) co_return tl::unexpected(sr.error());
  auto rp = co_await pump_until(udpop::SERVER_DESC_RES, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_server_desc(rp->payload, challenge);
}
}
