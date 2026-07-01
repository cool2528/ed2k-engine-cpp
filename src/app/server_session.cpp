#include "ed2k/app/server_session.hpp"
#include "ed2k/metfile/server_met.hpp"
#include "ed2k/util/error.hpp"
#include "ed2k/download/download.hpp"
#include "ed2k/peer/inbound_listener.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include <algorithm>
#include <exception>
#include <optional>
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

std::vector<ed2k::server::SourceEndpoint>
filter_high_id(const std::vector<ed2k::server::SourceEndpoint>& sources){
  std::vector<ed2k::server::SourceEndpoint> out;
  for(const auto& s : sources) if(!s.low_id()) out.push_back(s);
  return out;
}

boost::asio::awaitable<tl::expected<void, std::error_code>>
download_link(boost::asio::any_io_executor ex, const ed2k::Ed2kFileLink& link,
              std::span<const std::byte> met_bytes, std::optional<ServerTarget> override,
              const DownloadOpts& opts){
  ed2k::server::LoginParams p; p.nickname="ed2k-tool"; p.client_port=opts.client_port;
  p.user_hash = *ed2k::UserHash::from_hex("0123456789abcdeffedcba9876543210");
  auto lg = co_await login_with_rotation(ex, met_bytes, override, p, opts.per_server_timeout);
  if(!lg) co_return tl::unexpected(lg.error());
  auto gs = co_await lg->conn.get_sources(link.hash, link.size, opts.per_server_timeout);
  if(!gs) co_return tl::unexpected(gs.error());
  // M3: 不再 filter 掉 LowID —— HighID 直连, LowID 走回调(listener+server_conn)。
  // Fix(M3): 仅当存在 LowID 源时才构造 InboundListener。HighID-only 下载不需要
  // 监听器, 无条件 bind opts.client_port 会在端口被占用时抛 system_error, 回归
  // HighID 路径(本进程并发 download_link / 其它客户端占用 4662)。LowID 回调路径
  // 仍按原方式构造监听器。listener 生命周期覆盖整个 dl.run。
  // Fix(I1): InboundListener 构造仍可能抛 system_error(bind 失败: 端口被占用/
  // 权限不足)。download_link 是 expected<> 协程, CLI 以 asio::detached 派生无
  // 异常处理器, 抛出会穿出 io_context::run() -> std::terminate, 违反 spec §6.1
  // (无异常/CLI 不崩)。此处 try/catch 在调用点容纳该抛出: 失败则保持 listener
  // 为空, peer_worker 的 LowID 分支已有 `if(!server_conn || !listener) co_return
  // tl::unexpected(connect_failed)` 防御性守卫 -> LowID 源优雅跳过, HighID 源照常
  // 进行。InboundListener 的抛出式 ctor API 不变(Task 5 范围), 仅在调用点转换为
  // 干净的 expected 式降级(设置态, 非热路径)。
  bool has_low_id = std::any_of(gs->sources.begin(), gs->sources.end(),
                                [](const ed2k::server::SourceEndpoint& s){ return s.low_id(); });
  std::optional<ed2k::peer::InboundListener> listener;
  if(has_low_id){
    try { listener.emplace(ex, opts.client_port); }
    catch(const std::exception&) { /* bind 失败 — 保持 listener 为空; LowID 源优雅跳过 */ }
  }
  // M2: aich=nullopt -> MultiSourceDownload 走 part-MD4 兜底路径
  ed2k::download::MultiSourceDownload dl(ex, opts.out_path, link.hash, link.size,
                                         std::nullopt, std::move(gs->sources),
                                         &lg->conn, listener.has_value() ? &*listener : nullptr);
  co_return co_await dl.run(opts.total_timeout, 3);
}
}
