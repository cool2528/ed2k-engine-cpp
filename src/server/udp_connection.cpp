#include "ed2k/server/udp_connection.hpp"
#include "ed2k/net/udp_framing.hpp"
#include "ed2k/net/udp_obfuscation.hpp"
#include "ed2k/util/error.hpp"
#include <chrono>
#include <map>
#include <utility>
#include <vector>
namespace ed2k::server {
namespace asio = boost::asio;
using udp = asio::ip::udp;
using clock_type = std::chrono::steady_clock;

namespace {
bool matches_wanted_opcode(std::uint8_t got, std::uint8_t want){
  if(got == want) return true;
  return want == udpop::GLOBFOUNDSOURCES2 && got == udpop::GLOBFOUNDSOURCES;
}
}

struct UdpServerConnection::SubscriptionState {
  std::map<std::size_t, std::function<void(const UdpEvent&)>> sinks;
  std::size_t next_id = 1;
};

UdpServerConnection::Subscription::Subscription(std::weak_ptr<SubscriptionState> state, std::size_t id) noexcept
  : state_(std::move(state)), id_(id) {}
UdpServerConnection::Subscription::~Subscription() { reset(); }
UdpServerConnection::Subscription::Subscription(Subscription&& other) noexcept
  : state_(std::move(other.state_)), id_(std::exchange(other.id_, 0)) {}
UdpServerConnection::Subscription& UdpServerConnection::Subscription::operator=(Subscription&& other) noexcept {
  if(this != &other){
    reset();
    state_ = std::move(other.state_);
    id_ = std::exchange(other.id_, 0);
  }
  return *this;
}
void UdpServerConnection::Subscription::reset() noexcept {
  if(id_ == 0) return;
  if(auto state = state_.lock()) state->sinks.erase(id_);
  id_ = 0;
}

UdpServerConnection::UdpServerConnection(asio::any_io_executor ex, IPv4 ip, std::uint16_t port)
  : UdpServerConnection(ex, ip, port, UdpServerObfuscation{}) {}
UdpServerConnection::UdpServerConnection(asio::any_io_executor ex, IPv4 ip, std::uint16_t port,
                                         UdpServerObfuscation obfuscation)
  : sock_(ex),
    plain_server_(udp::endpoint(asio::ip::address_v4(ip.host()), port)),
    obfuscation_(obfuscation),
    observers_(std::make_shared<SubscriptionState>()) {}
UdpServerConnection::Subscription UdpServerConnection::on_event(std::function<void(const UdpEvent&)> sink){
  const auto id = observers_->next_id++;
  observers_->sinks.emplace(id, std::move(sink));
  return Subscription{observers_, id};
}
void UdpServerConnection::close() noexcept { sock_.close(); }

udp::endpoint UdpServerConnection::obfuscated_endpoint() const {
  return udp::endpoint(plain_server_.address(), obfuscation_.udp_port);
}

asio::awaitable<tl::expected<void,std::error_code>>
UdpServerConnection::send_request(const ed2k::net::Packet& request, bool obfuscated){
  if(obfuscated && obfuscation_.enabled()){
    auto clear = ed2k::net::encode_udp_packet(request);
    auto encoded = ed2k::net::encode_server_udp_obfuscated_datagram(
        clear,
        ed2k::net::ServerUdpObfuscationOptions{
            .base_key = obfuscation_.udp_key,
            .direction = ed2k::net::ServerUdpObfuscationDirection::client_to_server,
            .random_key_part = obfuscation_.random_key_part,
            .marker = obfuscation_.marker,
        });
    if(!encoded) co_return tl::unexpected(encoded.error());
    auto sr = co_await sock_.send_datagram(obfuscated_endpoint(), *encoded);
    if(!sr) co_return tl::unexpected(sr.error());
    co_return tl::expected<void,std::error_code>{};
  }
  auto sr = co_await sock_.send_to(plain_server_, request);
  if(!sr) co_return tl::unexpected(sr.error());
  co_return tl::expected<void,std::error_code>{};
}

asio::awaitable<tl::expected<ed2k::net::Packet,std::error_code>>
UdpServerConnection::request_response(const ed2k::net::Packet& request, std::uint8_t want,
                                      std::chrono::milliseconds timeout){
  last_response_encrypted_ = false;
  const auto deadline = clock_type::now() + timeout;
  const auto remaining = [&]() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
  };
  if(obfuscation_.enabled()){
    auto sr = co_await send_request(request, true);
    if(!sr) co_return tl::unexpected(sr.error());
    auto request_remaining = remaining();
    if(request_remaining.count() <= 0) co_return tl::unexpected(make_error_code(errc::timed_out));
    auto probe_timeout = obfuscation_.probe_timeout;
    if(probe_timeout.count() <= 0 || probe_timeout > request_remaining) probe_timeout = request_remaining;
    auto rp = co_await pump_until(want, probe_timeout);
    if(rp || !obfuscation_.fallback_plain || rp.error() != make_error_code(errc::timed_out)){
      co_return rp;
    }
  }
  if(remaining().count() <= 0) co_return tl::unexpected(make_error_code(errc::timed_out));
  auto sr = co_await send_request(request, false);
  if(!sr) co_return tl::unexpected(sr.error());
  auto request_remaining = remaining();
  if(request_remaining.count() <= 0) co_return tl::unexpected(make_error_code(errc::timed_out));
  co_return co_await pump_until(want, request_remaining);
}

asio::awaitable<tl::expected<ed2k::net::Packet,std::error_code>>
UdpServerConnection::pump_until(std::uint8_t want, std::chrono::milliseconds budget){
  auto deadline = clock_type::now() + budget;
  while(true){
    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
    if(rem.count() <= 0) co_return tl::unexpected(make_error_code(errc::timed_out));
    auto rp = co_await sock_.recv_datagram(rem);
    if(!rp) co_return tl::unexpected(rp.error());
    auto [datagram, sender] = std::move(*rp);
    const bool from_plain = sender == plain_server_;
    const bool from_obfuscated = obfuscation_.enabled() && sender == obfuscated_endpoint();
    if(!from_plain && !from_obfuscated) continue; // 过滤非目标源
    bool response_encrypted = false;
    if(obfuscation_.enabled()){
      auto decoded = ed2k::net::decode_server_udp_obfuscated_datagram(
          datagram,
          ed2k::net::ServerUdpObfuscationDecodeOptions{
              .base_key = obfuscation_.udp_key,
              .direction = ed2k::net::ServerUdpObfuscationDirection::server_to_client,
          });
      if(!decoded) co_return tl::unexpected(decoded.error());
      response_encrypted = decoded->encrypted;
      datagram = std::move(decoded->datagram);
    }
    auto parsed = ed2k::net::parse_udp_datagram(datagram);
    if(!parsed) co_return tl::unexpected(parsed.error());
    last_response_encrypted_ = response_encrypted;
    auto pkt = std::move(*parsed);
    if(matches_wanted_opcode(pkt.opcode, want)) co_return std::move(pkt);
    auto dispatch = [&](UdpEvent event) {
      std::vector<std::function<void(const UdpEvent&)>> sinks;
      sinks.reserve(observers_->sinks.size());
      for(auto& [id, sink] : observers_->sinks) sinks.push_back(sink);
      for(auto& sink : sinks) sink(event);
    };
    if(pkt.opcode == udpop::INVALID_LOWID){
      if(!observers_->sinks.empty()){
        auto id = decode_invalid_low_id(pkt.payload);
        if(id) dispatch(InvalidLowIdEvent{*id});
      }
      continue;
    }
    if(pkt.opcode == udpop::SERVER_IDENT){
      if(!observers_->sinks.empty()){
        auto id = decode_udp_server_ident(pkt.payload);
        if(id) dispatch(UdpServerIdentEvent{id->hash, id->ip, id->port, id->name, id->description});
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
  auto rp = co_await request_response(req, udpop::GLOBSEARCHRES, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_glob_search_res(rp->payload);
}
asio::awaitable<tl::expected<FoundSources,std::error_code>>
UdpServerConnection::get_sources(const FileHash& h, std::uint64_t size, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=udpop::GLOBGETSOURCES2;
  req.payload = encode_get_sources_req(h, size);
  auto rp = co_await request_response(req, udpop::GLOBFOUNDSOURCES2, timeout);
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
  auto rp = co_await request_response(req, udpop::GLOBSERVSTATRES, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_server_stat(rp->payload, challenge);
}
asio::awaitable<tl::expected<std::vector<std::pair<IPv4,std::uint16_t>>,std::error_code>>
UdpServerConnection::server_list(IPv4 ask_ip, std::uint16_t ask_port, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=udpop::SERVER_LIST_REQ;
  req.payload = encode_server_list_req(ask_ip, ask_port);
  auto rp = co_await request_response(req, udpop::SERVER_LIST_RES, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_server_list(rp->payload);
}
asio::awaitable<tl::expected<ServerDesc,std::error_code>>
UdpServerConnection::server_desc(std::uint32_t challenge, std::chrono::milliseconds timeout){
  ed2k::net::Packet req; req.protocol=ed2k::net::proto::eDonkey; req.opcode=udpop::SERVER_DESC_REQ;
  req.payload = encode_server_desc_req(challenge);
  auto rp = co_await request_response(req, udpop::SERVER_DESC_RES, timeout);
  if(!rp) co_return tl::unexpected(rp.error());
  co_return decode_server_desc(rp->payload, challenge);
}
}
