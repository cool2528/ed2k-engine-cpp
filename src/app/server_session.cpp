#include "ed2k/app/server_session.hpp"
#include "ed2k/metfile/server_met.hpp"
#include "ed2k/util/error.hpp"
#include <unordered_set>
namespace ed2k::app {
std::vector<ServerTarget> fallback_servers(){
  // spec §6.5 内建可达服务器（自探测 8/9 可达）
  auto add=[](std::vector<ServerTarget>& v, const char* ip, std::uint16_t p){
    if(auto x=IPv4::from_dotted(ip)) v.push_back({*x, p});
  };
  std::vector<ServerTarget> v;
  add(v, "45.82.80.155", 5687);
  add(v, "176.123.5.89", 4725);
  add(v, "91.208.162.87", 4232);
  add(v, "85.121.5.137", 4232);
  add(v, "77.42.68.79", 4232);
  add(v, "91.208.162.182", 4232);
  add(v, "213.141.198.207", 4232);
  add(v, "45.87.41.16", 6262);
  return v;
}
std::vector<ServerTarget> build_targets(std::span<const std::byte> met_bytes,
                                        std::optional<ServerTarget> override){
  std::vector<ServerTarget> out;
  std::unordered_set<std::uint64_t> seen;
  auto push=[&](const ServerTarget& t){
    std::uint64_t k = (std::uint64_t(t.ip.value) << 16) | t.port;
    if(seen.insert(k).second) out.push_back(t);
  };
  if(override) push(*override);
  if(auto sl = parse_server_met(met_bytes)){
    for(const auto& s : sl->servers) push({s.ip, s.port});
  }
  for(const auto& t : fallback_servers()) push(t);
  return out;
}
boost::asio::awaitable<tl::expected<LoginSession, std::error_code>>
login_with_rotation(boost::asio::any_io_executor ex,
                    std::span<const std::byte> met_bytes,
                    std::optional<ServerTarget> override,
                    const ed2k::server::LoginParams& p,
                    std::chrono::milliseconds per_server_timeout){
  auto targets = build_targets(met_bytes, override);
  std::error_code last = make_error_code(errc::connect_failed);
  for(const auto& t : targets){
    ed2k::server::ServerConnection conn(ex);
    auto r = co_await conn.connect_and_login(t.ip, t.port, p, per_server_timeout);
    if(r.has_value()) co_return LoginSession{std::move(conn), *r};
    last = r.error();
    conn.close();
  }
  co_return tl::unexpected(last);
}
}
