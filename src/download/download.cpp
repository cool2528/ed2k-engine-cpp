#include "ed2k/download/download.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/download/block_allocator.hpp"
#include "ed2k/download/aich_checker.hpp"
#include "ed2k/kad/network.hpp"
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/peer/peer_reask.hpp"
#include "ed2k/net/udp_socket.hpp"
#include "ed2k/util/error.hpp"
#include <algorithm>
#include <optional>
#include <cassert>
#include <thread>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
namespace ed2k::download {
namespace {
kad::KadID kad_id_from_hash(const FileHash& hash) {
  return kad::KadID::from_bytes(hash.bytes());
}

std::uint32_t ipv4_to_wire(IPv4 ip) noexcept {
  const auto host = ip.host();
  return ((host & 0x000000ffu) << 24) |
         ((host & 0x0000ff00u) << 8) |
         ((host & 0x00ff0000u) >> 8) |
         ((host & 0xff000000u) >> 24);
}

bool same_source(const server::SourceEndpoint& lhs, const server::SourceEndpoint& rhs) noexcept {
  return lhs.id == rhs.id && lhs.port == rhs.port;
}

// Task 6 错误分类: 判断源级失败应"退避重连同一源/编排监督稍后重试"(transient)还是应"彻底
// 放弃该源"(terminal)。
// TRANSIENT — 与网络层瞬时状态相关, 同源换一次连接/等一等大概率能恢复:
//   - timed_out:         握手/请求超时(对端一时无响应, 不代表源已失效)。
//   - connection_closed: 连接被对端关闭/读写失败(EOF、RST 等, 见 net::Connection 的错误映射)。
//   - upload_queued:     排队等待放弃(queue_wait_phase 里 reask 收到 QUEUEFULL——源此刻上传槽
//                        满, 不代表源没有这个文件; kQueueWaitMax 耗尽走的是 timed_out, 已覆盖)。
// TERMINAL — 与"这个源到底有没有这个文件/数据是否正确"相关的确定性判断, 重连不会改变结论,
// 因此除上面显式列出的以外一律按 terminal 处理(含 file_not_found/hash_mismatch/block_corrupt/
// connect_failed/ip_filtered 等, 以及未来新增错误码如 Task 7 的双 LowID——不了解语义的错误码
// 默认不重试, 比默认重试更安全)。
bool is_transient(std::error_code ec) noexcept {
  return ec == make_error_code(errc::timed_out) ||
         ec == make_error_code(errc::connection_closed) ||
         ec == make_error_code(errc::upload_queued);
}

std::optional<server::SourceEndpoint> endpoint_from_kad_source(const kad::KadSearchEntry& entry) {
  const auto type = kad::source_type(entry);
  if (type != 1 && type != 4) {
    return std::nullopt;
  }
  const auto ip = kad::source_ip(entry);
  const auto tcp_port = kad::source_tcp_port(entry);
  if (!ip || ip->host() == 0 || tcp_port == 0) {
    return std::nullopt;
  }
  return server::SourceEndpoint{ipv4_to_wire(*ip), tcp_port};
}

peer::HelloInfo default_hello(peer::ObfuscationPolicy policy = peer::ObfuscationPolicy::disabled,
                              std::optional<UserHash> local_user_hash = std::nullopt) {
  peer::HelloInfo mine;
  mine.user_hash = local_user_hash.value_or(
      *ed2k::UserHash::from_hex("0123456789abcdeffedcba9876543210"));
  mine.nickname = "ed2k";
  mine.version = 0x3C;
  mine.port = 4662;
  mine.supports_obfuscation = policy != peer::ObfuscationPolicy::disabled;
  mine.requests_obfuscation = policy != peer::ObfuscationPolicy::disabled;
  mine.requires_obfuscation = policy == peer::ObfuscationPolicy::required;
  return mine;
}

// 我方在 mule-info 握手中通告的信息。udp_port 保持默认值 0: 本引擎的上传/分享侧
// (share::UploadSession) 尚未实现入站 UDP reask 应答 (设计文档 P2 的 A8), 在那之前如实
// 通告"不可达", 避免让对端 (若把我方当上传源) 误判我方支持 UDP reask。其余字段沿用
// MuleInfo 的默认值 (已是符合 aMule 惯例的协议标识)。
peer::MuleInfo default_mule_info() {
  return peer::MuleInfo{};
}

std::size_t data_part_count(std::uint64_t size) noexcept {
  return static_cast<std::size_t>((size + PART_SIZE - 1) / PART_SIZE);
}

std::vector<bool> normalize_file_status_parts(std::vector<bool> parts, std::uint64_t size) {
  // aMule 对完整共享文件发 FILESTATUS count=0 (无 part 位图): ClientTCPSocket.cpp OP_SETREQFILEID
  // 处理 `if(reqfile->IsPartFile()) WritePartStatus else WriteUInt16(0)`。语义 = 对端拥有整文件
  // (所有 part 可用), 不是 "0 part"。非空位图 (PartFile 不完整源) 按实际 have-part 过滤。
  if(parts.empty()) parts.assign(data_part_count(size), true);
  return parts;
}

struct FileSetup {
  std::vector<PartHash> part_hashes;
  std::vector<bool> peer_parts;
  std::uint16_t source_udp_port = 0;   // 源通告的 UDP 端口 (ET_UDPPORT); 0=未通告/纯 eDonkey
};

boost::asio::awaitable<tl::expected<FileSetup,std::error_code>>
fetch_hashset_phase(peer::C2CConnection& conn,
                    const FileHash& hash,
                    std::uint64_t size,
                    std::chrono::milliseconds timeout) {
  auto fs = co_await conn.request_file(hash, timeout);
  if(!fs) co_return tl::unexpected(fs.error());
  // 单 part 文件跳过 hashset (aMule 不应答); 传空 part_hashes, PartFile 自合成 {file_hash}。
  std::vector<PartHash> part_hashes;
  if(size > PART_SIZE){
    auto hs = co_await conn.request_hashset(hash, timeout);
    if(!hs) co_return tl::unexpected(hs.error());
    part_hashes = std::move(*hs);
  }
  co_return FileSetup{std::move(part_hashes), normalize_file_status_parts(std::move(fs->parts), size)};
}

// P0 架构决策#3: 返回 UploadOutcome(而非过去丢弃结果的 void)——Accepted/Queued{rank} 均是
// eD2k 协议的正常路径, 由调用方(peer_worker)决定是否需要进入排队等待循环。Download::run()
// (单源, 非 raccoon 路径) 目前仍只检查 !upload 而不消费具体结果, 保留其既有行为不变
// (该单源路径不在本任务范围, 见 task-5 report 的 Concerns)。
boost::asio::awaitable<tl::expected<peer::UploadOutcome,std::error_code>>
start_upload_phase(peer::C2CConnection& conn,
                   const FileHash& hash,
                   std::chrono::milliseconds timeout) {
  (void)co_await conn.request_filename(hash, timeout);   // 文件名可选,忽略失败
  co_return co_await conn.start_upload(hash, timeout);
}

boost::asio::awaitable<tl::expected<void,std::error_code>>
dispatch_blocks_phase(peer::C2CConnection& conn,
                      PartFile& pf,
                      const FileHash& hash,
                      std::uint64_t size,
                      std::vector<bool> peer_parts,
                      std::chrono::milliseconds timeout) {
  auto missing = pf.missing_parts_peer_has(peer_parts);
  // 缺失 part 位图: 用于跳过对端没有 / 已完成的 part。
  std::vector<bool> need_part(data_part_count(size), false);
  for(std::uint32_t p : missing) need_part[p] = true;
  // per-part 块迭代: 块绝不跨 part 边界, 与 aMule 两级树 per-part 叶序一致。
  std::size_t np = data_part_count(size);
  for(std::size_t p=0; p<np; ++p){
    if(p >= need_part.size() || !need_part[p]) continue;
    std::uint64_t pstart = static_cast<std::uint64_t>(p) * PART_SIZE;
    std::uint64_t plen = std::min(PART_SIZE, size - pstart);
    std::size_t nb = static_cast<std::size_t>((plen + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE);
    for(std::size_t b=0; b<nb; ++b){
      if(pf.is_block_done(p, b)) continue;
      std::uint64_t start = pstart + static_cast<std::uint64_t>(b) * AICH_BLOCK_SIZE;
      std::uint64_t end = std::min(start + AICH_BLOCK_SIZE, pstart + plen);
      auto blocks = co_await conn.request_blocks(hash,
        std::array<std::uint32_t,3>{static_cast<std::uint32_t>(start),0,0},
        std::array<std::uint32_t,3>{static_cast<std::uint32_t>(end),0,0},
        timeout);
      if(!blocks) co_return tl::unexpected(blocks.error());
      if(blocks->empty()) co_return tl::unexpected(make_error_code(errc::io_error));   // 避免空响应死循环
      for(auto& b2 : *blocks){
        auto w = pf.write_block(b2.start, b2.end, b2.data);
        if(!w) co_return tl::unexpected(w.error());
      }
    }
  }
  co_return tl::expected<void,std::error_code>{};
}
} // namespace

std::optional<peer::PeerIdentity>
peer_identity_from_kad_source(const kad::KadSearchEntry& entry) {
  auto endpoint = endpoint_from_kad_source(entry);
  if (!endpoint) return std::nullopt;
  return peer::PeerIdentity{*endpoint, UserHash::from_bytes(entry.answer_id.bytes())};
}

Download::Download(boost::asio::any_io_executor ex, const std::filesystem::path& out,
                   const FileHash& hash, std::uint64_t size, const ed2k::server::SourceEndpoint& source)
  : Download(ex, out, hash, size, peer::PeerIdentity{source, std::nullopt},
             peer::ObfuscationPolicy::disabled) {}

Download::Download(boost::asio::any_io_executor ex, const std::filesystem::path& out,
                   const FileHash& hash, std::uint64_t size, peer::PeerIdentity source,
                   peer::ObfuscationPolicy policy, std::optional<UserHash> local_user_hash)
  : conn_(ex), out_(out), hash_(hash), size_(size), source_(std::move(source)),
    obfuscation_policy_(policy), local_user_hash_(std::move(local_user_hash)) {}

void Download::set_ip_filter(std::shared_ptr<const infra::IPFilter> filter, std::uint8_t level) {
  ip_filter_ = std::move(filter);
  ip_filter_level_ = level;
  conn_.set_ip_filter(ip_filter_, ip_filter_level_);
}

boost::asio::awaitable<tl::expected<void,std::error_code>>
Download::run(std::chrono::milliseconds timeout){
  conn_.set_ip_filter(ip_filter_, ip_filter_level_);
  auto cr = co_await conn_.connect(source_, obfuscation_policy_, timeout);
  if(!cr) co_return tl::unexpected(cr.error());
  auto hr = co_await conn_.handshake_with_mule_info(default_hello(obfuscation_policy_, local_user_hash_),
                                                    default_mule_info(), timeout);
  if(!hr) co_return tl::unexpected(hr.error());
  source_udp_port_ = hr->mule_info.udp_port;
  auto setup = co_await fetch_hashset_phase(conn_, hash_, size_, timeout);
  if(!setup) co_return tl::unexpected(setup.error());
  setup->source_udp_port = source_udp_port_;
  PartFile pf(out_, size_, hash_, std::move(setup->part_hashes));
  auto upload = co_await start_upload_phase(conn_, hash_, timeout);
  if(!upload) co_return tl::unexpected(upload.error());
  auto dispatched = co_await dispatch_blocks_phase(conn_, pf, hash_, size_,
                                                   std::move(setup->peer_parts), timeout);
  if(!dispatched) co_return tl::unexpected(dispatched.error());
  if(!pf.complete()) co_return tl::unexpected(make_error_code(errc::io_error));
  co_return tl::expected<void,std::error_code>{};
}

struct MultiSourceDownload::Impl {
  Impl(boost::asio::any_io_executor net_ex,
       boost::asio::any_io_executor disk_ex_arg,
       std::filesystem::path out_arg, FileHash hash_arg, std::uint64_t size_arg,
       std::optional<AICHHash> aich_arg,
       std::vector<peer::PeerIdentity> sources_arg,
       std::optional<std::reference_wrapper<server::ServerConnection>> server_conn_arg,
       std::optional<std::reference_wrapper<peer::InboundListener>> listener_arg,
       std::optional<std::reference_wrapper<kad::KadNetwork>> kad_network_arg,
       std::vector<kad::Contact> kad_peers_arg,
       std::shared_ptr<const infra::IPFilter> ip_filter_arg,
       std::uint8_t ip_filter_level_arg,
       peer::ObfuscationPolicy obfuscation_policy_arg,
       std::optional<UserHash> local_user_hash_arg,
       ProgressFn on_progress_arg,
       std::shared_ptr<const bool> stop_arg)
    : ex(net_ex), disk_ex(std::move(disk_ex_arg)), out(std::move(out_arg)), hash(hash_arg), size(size_arg),
      aich(std::move(aich_arg)), sources(std::move(sources_arg)),
      server_conn(std::move(server_conn_arg)), listener(std::move(listener_arg)),
      kad_network(std::move(kad_network_arg)), kad_peers(std::move(kad_peers_arg)),
      ip_filter(std::move(ip_filter_arg)),
      ip_filter_level(ip_filter_level_arg), obfuscation_policy(obfuscation_policy_arg),
      local_user_hash(std::move(local_user_hash_arg)), on_progress(std::move(on_progress_arg)),
      stop(std::move(stop_arg)) {}

  boost::asio::any_io_executor ex;
  boost::asio::any_io_executor disk_ex;   // 默认 = ex (同步等效), Builder.disk_executor 注入 disk 池
  std::filesystem::path out;
  FileHash hash;
  std::uint64_t size;
  std::optional<AICHHash> aich;
  std::vector<peer::PeerIdentity> sources;
  std::optional<std::reference_wrapper<server::ServerConnection>> server_conn;
  std::optional<std::reference_wrapper<peer::InboundListener>> listener;
  std::optional<std::reference_wrapper<kad::KadNetwork>> kad_network;
  // B4: kad_network 若为 ephemeral 实例(自己的路由表为空), run() 不能再从它自己的路由表取
  // peers——必须由调用方(如 Session::run_task)从主路由表快照后显式传入。与 kad_network 是
  // "有没有 Kad 网络对象可用"和"该向谁发 find_sources 请求"两个独立维度。
  std::vector<kad::Contact> kad_peers;
  std::shared_ptr<const infra::IPFilter> ip_filter;
  std::uint8_t ip_filter_level = 127;
  peer::ObfuscationPolicy obfuscation_policy = peer::ObfuscationPolicy::disabled;
  std::optional<UserHash> local_user_hash;
  ProgressFn on_progress;
  std::shared_ptr<const bool> stop;
};

MultiSourceDownload::MultiSourceDownload(boost::asio::any_io_executor ex,
                                          const std::filesystem::path& out,
                                          const FileHash& hash, std::uint64_t size,
                                          const std::optional<AICHHash>& aich,
                                          std::vector<server::SourceEndpoint> sources,
                                          server::ServerConnection* server_conn,
                                          peer::InboundListener* listener)
  : impl_(std::make_unique<Impl>(
      ex, ex, out, hash, size, aich, [&] {
        std::vector<peer::PeerIdentity> peers;
        peers.reserve(sources.size());
        for (auto& endpoint : sources) peers.push_back(peer::PeerIdentity{endpoint, std::nullopt});
        return peers;
      }(),
      server_conn ? std::optional<std::reference_wrapper<server::ServerConnection>>(std::ref(*server_conn)) : std::nullopt,
      listener ? std::optional<std::reference_wrapper<peer::InboundListener>>(std::ref(*listener)) : std::nullopt,
      std::nullopt, std::vector<kad::Contact>{}, nullptr, 127, peer::ObfuscationPolicy::disabled,
      std::nullopt, nullptr, nullptr)) {}

MultiSourceDownload::MultiSourceDownload(boost::asio::any_io_executor net_ex,
                                         boost::asio::any_io_executor disk_ex,
                                         std::filesystem::path out, FileHash hash, std::uint64_t size,
                                         std::optional<AICHHash> aich,
                                         std::vector<peer::PeerIdentity> sources,
                                         std::optional<std::reference_wrapper<server::ServerConnection>> server_conn,
                                         std::optional<std::reference_wrapper<peer::InboundListener>> listener,
                                         std::optional<std::reference_wrapper<kad::KadNetwork>> kad_network,
                                         std::vector<kad::Contact> kad_peers,
                                         std::shared_ptr<const infra::IPFilter> ip_filter,
                                         std::uint8_t ip_filter_level,
                                         peer::ObfuscationPolicy obfuscation_policy,
                                         std::optional<UserHash> local_user_hash,
                                         ProgressFn on_progress,
                                         std::shared_ptr<const bool> stop)
  : impl_(std::make_unique<Impl>(net_ex, std::move(disk_ex), std::move(out), hash, size,
                                 std::move(aich), std::move(sources), std::move(server_conn),
                                 std::move(listener), std::move(kad_network), std::move(kad_peers),
                                 std::move(ip_filter), ip_filter_level, obfuscation_policy,
                                 std::move(local_user_hash),
                                 std::move(on_progress), std::move(stop))) {}

MultiSourceDownload::~MultiSourceDownload() = default;
MultiSourceDownload::MultiSourceDownload(MultiSourceDownload&&) noexcept = default;
MultiSourceDownload& MultiSourceDownload::operator=(MultiSourceDownload&&) noexcept = default;

void MultiSourceDownload::set_disk_executor(boost::asio::any_io_executor ex) {
  impl_->disk_ex = std::move(ex);
}

MultiSourceDownload MultiSourceDownload::Builder::build() {
  return MultiSourceDownload(net_ex_, disk_ex_, std::move(out_), hash_, size_,
                             std::move(aich_), std::move(sources_),
                             std::move(server_), std::move(listener_),
                             std::move(kad_network_), std::move(kad_peers_),
                             std::move(ip_filter_), ip_filter_level_,
                             obfuscation_policy_, std::move(local_user_hash_),
                             std::move(on_progress_), std::move(stop_));
}

// === raccoon 多源并发 (P4c-3) ===
// 设计 spec §3: 单 io_context/单网络线程 + co_spawn 多 worker + 共享无锁状态。
// 块分发 = 同步 next_block_for_parts(has_part) (非阻塞 pop, 按对端 part 位图过滤);
// 完成信号 = asio::experimental::channel (awaitable, 不阻塞线程)。禁用 condition_variable
// (会阻塞唯一网络线程 → 死锁)。PartFile/BlockAllocator/SharedState 仅网络线程访问 → 无 mutex。
//
// fetch_hashset: setup 阶段顺序从首个可用源拿 hashset (鸡生蛋: 共享 PartFile/BlockAllocator
// 构造依赖 part_hashes)。其连接复用给该源 worker (设计 spec §1.4: 连接复用, 免重连)。
struct FetchResult {
  std::vector<PartHash> part_hashes;
  std::vector<bool> fs_parts;                     // 对端 part 可用位图 (FILESTATUS)
  std::optional<ed2k::peer::C2CConnection> conn;  // setup 连接, 复用给该源 worker
  std::uint16_t source_udp_port = 0;              // 源通告的 UDP 端口; 0=未通告/纯 eDonkey
};
static boost::asio::awaitable<tl::expected<FetchResult,std::error_code>>
fetch_hashset(boost::asio::any_io_executor ex,
              const ed2k::peer::PeerIdentity& source, const FileHash& hash,
              std::uint64_t size,
              std::chrono::milliseconds timeout,
              std::optional<std::reference_wrapper<ed2k::server::ServerConnection>> server_conn,
              std::optional<std::reference_wrapper<ed2k::peer::InboundListener>> listener,
              std::shared_ptr<const infra::IPFilter> ip_filter,
              std::uint8_t ip_filter_level,
              ed2k::peer::ObfuscationPolicy obfuscation_policy,
              std::optional<UserHash> local_user_hash){
  bool accepted = false;   // LowID 回调路径下我方是 TCP acceptor, 握手角色随之翻转
  std::optional<ed2k::peer::C2CConnection> conn_opt;
  if(source.endpoint.low_id()){
    if(!server_conn || !listener) co_return tl::unexpected(make_error_code(errc::connect_failed));
    auto cb = co_await server_conn->get().callback_request(source.endpoint.id, timeout);
    if(!cb) co_return tl::unexpected(cb.error());
    auto acc = co_await listener->get().accept_peer(local_user_hash, obfuscation_policy, timeout,
                                                     ip_filter, ip_filter_level);
    if(!acc) co_return tl::unexpected(acc.error());
    conn_opt.emplace(std::move(*acc));
    accepted = true;
  } else {
    ed2k::peer::C2CConnection c(ex);
    c.set_ip_filter(ip_filter, ip_filter_level);
    auto cr = co_await c.connect(source, obfuscation_policy, timeout);
    if(!cr) co_return tl::unexpected(cr.error());
    conn_opt.emplace(std::move(c));
    accepted = false;
  }
  tl::expected<ed2k::peer::C2CHandshakeResult,std::error_code> hr;
  if(accepted) hr = co_await conn_opt->handshake_acceptor_with_mule_info(
      default_hello(obfuscation_policy, local_user_hash), default_mule_info(), timeout);
  else         hr = co_await conn_opt->handshake_with_mule_info(
      default_hello(obfuscation_policy, local_user_hash), default_mule_info(), timeout);
  if(!hr) co_return tl::unexpected(hr.error());
  auto fs = co_await conn_opt->request_file(hash, timeout);
  if(!fs) co_return tl::unexpected(fs.error());
  // 单 part 文件 (size <= PARTSIZE): aMule GetHashCount()==0 → SendHashsetPacket 静默不发
  // OP_HASHSETANSWER (UploadClient.cpp SendHashsetPacket 守卫: !file->GetHashCount() 即 return)。
  // 协议正确语义: 单 part 文件无独立 part-hashset, 文件 hash 即唯一 part hash。跳过请求,
  // 传空 part_hashes 让 PartFile 构造器自合成 {file_hash} (part_file.cpp:13)。多 part 文件照常请求。
  std::vector<PartHash> part_hashes;
  if(size > PART_SIZE){
    auto hs = co_await conn_opt->request_hashset(hash, timeout);
    if(!hs) co_return tl::unexpected(hs.error());
    part_hashes = std::move(*hs);
  }
  FetchResult r;
  r.part_hashes = std::move(part_hashes);
  r.fs_parts = std::move(fs->parts);
  r.conn = std::move(conn_opt);
  r.source_udp_port = hr->mule_info.udp_port;
  co_return r;
}

// === P0 排队等待重构: 排队等待用的常量与共享 UDP reask 基础设施 ===
// 排队存活总上限(架构决策#2 第③层): 独立于 per-op 快超时, 只要有 inbound(REASKACK/QUEUERANKING/
// 任何帧)就在 queue_wait_phase 里刷新; 只有连接真正沉默/死掉才会触发。可被 st.stop/取消提前打断。
inline constexpr std::chrono::minutes kQueueWaitMax{30};
// 单次 reask 的往返预算(短, 与 kReaskInterval=60s 的排队间隔解耦, 见 peer_reask.hpp 顶部注释与
// 架构决策#1): 让串行化的调用不会拖得比间隔还长。
inline constexpr std::chrono::milliseconds kReaskCallTimeout{3000};
// queue_wait_phase 里"继续监听 TCP 同时做一次 reask"的竞速(见该函数注释)中, TCP 侧的预算比
// kReaskCallTimeout 多出的余量——保证 reask 自身的超时总是先于这个 TCP 预算到期, 使 TCP 分支
// 只可能因为"确实收到了新帧"而提前赢得竞速, 不会因为自己的超时抢先(令 reask 的结果被白白丢弃)。
inline constexpr std::chrono::milliseconds kReaskRaceMargin{500};

// === Task 6: 源重试/重连 + 编排周期重问的常量与取消安全等待基础设施 ===
// 单个 peer_worker 对同一源的 transient 重连上限(不含最初一次连接; 与本文件既有的
// max_retries/AICH 块级重试计数同一约定——"N 次重试"=最初一次 + N 次重试, 见 pull_blocks_phase
// 里 `++retry > max_retries` 的计数方式)。达到上限后彻底放弃该源(转交编排监督, 见下), 而不是
// 无限重连同一个可能已经不可达的源。
inline constexpr std::size_t kMaxSourceReconnect = 3;
// 编排监督(source_reask_supervisor)的"无源可用"有界放弃阈值(Task 6 review 修复 Important#1):
// 连续这么多轮周期重问都既没合并到新源、又没有 transient 重试源、且当前无任何活跃 worker(源已
// 彻底耗尽, 服务器也提供不了新源)时, 监督退出、run() 以源耗尽错误(first_err/io_error)返回, 而不是
// 永久挂在 downloading/0B/s 白占一个并发下载槽。取 3(配合默认 3 分钟周期≈最多多等 ~9 分钟)给晚到
// 的源留机会但有上界; 任一进展(合并到新源、有重试源、或仍有活跃 worker)即把计数清零重新计。
inline constexpr std::size_t kMaxEmptyReaskCycles = 3;
// 可取消等待(退避重连 / 监督重问定时器)的轮询切片粒度: 与其一次性睡满整段时长, 不如切成短片段
// 循环, 每片之间重新检查 st.stopped()/st.alloc.complete()——保证 cancel/shutdown 或"文件已被
// 其它源下完"能在一个切片内被发现, 而不是被整段退避/3 分钟定时器"吞掉"。取值参考本文件既有的
// 轮询式取消检查粒度(如 session.cpp accept_loop 的 1s 轮询), 200ms 足够快又不至于空转过密。
inline constexpr std::chrono::milliseconds kCancellableWaitSlice{200};
// cancellable_wait() 的实现见 SharedState 定义之后(依赖 SharedState::stopped()/alloc)。
// done_ch(ResultCh) 容量相对初始 worker 数的余量: 覆盖 source_reask_supervisor 动态增补的新源/
// transient 重试源(单次 GETSOURCES 应答受协议 u8 计数上限 255, 加上重试池, 留足余量避免
// try_send 因容量不足而静默丢 token——那会让 run() 的收尾等待永久挂起, 见 run() 内注释)。
inline constexpr std::size_t kDoneChannelHeadroom = 1024;

// 排队等待 UDP reask 的串行化门闸(架构决策#1): net::UdpSocket::recv_datagram 是裸
// async_receive_from, 不支持多路等待者(peer_reask.hpp 顶部注释已详述该限制)。用容量=1 的
// channel 当二元信号量: 取到令牌(recv 成功)= 获得排他使用权; try_send 放回令牌 = 释放。
// 一个共享 UdpSocket + 一个共享 ReaskGate 活在 SharedState 一级, 所有 peer_worker 的排队等待
// 循环共用同一份, 保证同一时刻至多一个 reask_source 调用在等待该 socket 的 recv。
using ReaskGate = boost::asio::experimental::channel<void(boost::system::error_code)>;

// 持有 ReaskGate 令牌期间的 RAII: 析构时放回令牌, 覆盖"正常用完"与"被 || 取消, 协程收尾"两种
// 路径(awaitable_operators 的 wait_for_one_success 保证输家协程会跑完自己的收尾逻辑, 而不是被
// 直接销毁——析构函数因此总会被调用, 见 queue_wait_phase 里的使用)。只能通过 reask_gate_acquire
// 构造(已获得令牌后才允许持有本对象)。
struct ReaskGateGuard {
  ReaskGate* gate;
  explicit ReaskGateGuard(ReaskGate& g) : gate(&g) {}
  ~ReaskGateGuard(){ if(gate) gate->try_send(boost::system::error_code{}); }
  ReaskGateGuard(const ReaskGateGuard&) = delete;
  ReaskGateGuard& operator=(const ReaskGateGuard&) = delete;
  ReaskGateGuard(ReaskGateGuard&& other) noexcept : gate(other.gate) { other.gate = nullptr; }
  ReaskGateGuard& operator=(ReaskGateGuard&&) = delete;
};
boost::asio::awaitable<ReaskGateGuard> reask_gate_acquire(ReaskGate& gate){
  co_await gate.async_receive(boost::asio::use_awaitable);   // 容量1: 拿不到令牌就在此挂起等释放
  co_return ReaskGateGuard(gate);
}

// 共享状态 (仅网络线程访问 → 无锁)。PartFile/BlockAllocator 跨 worker 共享; AICHChecker
// 无状态, setup 后构造一次共享; aich_active 为 per-worker (每 worker 与己方 peer 协商 master)。
struct SharedState {
  PartFile pf;
  BlockAllocator alloc;
  std::optional<AICHChecker> checker;
  std::optional<AICHHash> aich;
  FileHash hash;
  std::uint64_t size;
  boost::asio::any_io_executor disk_ex;   // M3: PartFile::write_block_async 卸载用
  net::UdpSocket reask_sock;              // 排队等待 UDP reask 共享 socket (架构决策#1)
  ReaskGate reask_gate;                   // 上述 socket 的串行化门闸; 构造后立即塞一个令牌(见 run())
  bool complete = false;
  std::size_t active_workers = 0;
  std::optional<std::error_code> first_err;
  std::uint64_t bytes_done = 0;
  ProgressFn on_progress;
  std::shared_ptr<const bool> stop;
  // Task 6: source_reask_supervisor 是否仍存活。run() 的收尾等待循环据此判断——只要它还在跑,
  // 就可能继续增补新 worker(active_workers 因此可能回升), run() 就不能提前返回析构本 SharedState
  // (supervisor 持有 SharedState&, 提前析构 = 悬垂引用)。仅由 run()(启动前置 true)与
  // source_reask_supervisor 自身(退出前置 false)读写, 同一网络线程, 无锁。
  bool supervisor_active = false;
  // Task 6: 已耗尽 kMaxSourceReconnect 预算、最终仍以 transient 错误放弃的源池——供
  // source_reask_supervisor 周期性取走并重新尝试(全新 peer_worker 调用, 拿到全新重连预算)。
  // terminal 放弃的源不进这个池(重试没有意义)。
  std::vector<peer::PeerIdentity> transient_retry_pool;
  bool stopped() const noexcept { return stop && *stop; }
  void add_progress(std::uint64_t n) {
    assert_owner();
    bytes_done += n;
    if(on_progress) on_progress(bytes_done, size);
  }
#ifndef NDEBUG
  std::thread::id owner_thread = std::this_thread::get_id();
  void assert_owner() const { assert(owner_thread == std::this_thread::get_id()); }
#else
  void assert_owner() const noexcept {}
#endif
  void set_error(std::error_code ec) {
    assert_owner();
    if(ec && !first_err) first_err = ec;
  }
  void dec_active_workers() {
    assert_owner();
    if(active_workers > 0) --active_workers;
  }
  void mark_complete() {
    assert_owner();
    complete = true;
  }
};

// 可取消的定时等待(Task 6): 睡眠 duration, 但按 kCancellableWaitSlice 切片轮询, 一旦
// st.stopped()(用户取消/Session::shutdown)或 st.alloc.complete()(整文件已被其它源下完, 无需
// 再等)命中即立即返回, 不吞掉这两类信号。供 peer_worker 的退避重连与 source_reask_supervisor
// 的周期定时器共用——调用方返回后自行重新检查这两个条件决定下一步(继续重连/重问, 还是收尾
// 退出), 本函数不区分"等满"/"被提前唤醒"这两种返回路径(调用方的后续检查已经足够)。
static boost::asio::awaitable<void>
cancellable_wait(SharedState& st, boost::asio::any_io_executor ex, std::chrono::milliseconds duration){
  using clock_type = std::chrono::steady_clock;
  const auto deadline = clock_type::now() + duration;
  boost::asio::steady_timer timer(ex);
  while(clock_type::now() < deadline){
    if(st.stopped() || st.alloc.complete()) co_return;
    const auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
    const auto step = std::min(kCancellableWaitSlice, std::max(remain, std::chrono::milliseconds{0}));
    if(step <= std::chrono::milliseconds{0}) co_return;
    timer.expires_after(step);
    co_await timer.async_wait(boost::asio::use_awaitable);
  }
}

// 完成信号 channel: worker/supervisor 退出时 try_send 发一个 token; run() 按状态驱动收 token。
// 签名 void(boost::system::error_code, int): 首参 error_code 被 use_awaitable 当操作状态
// (始终 success), int 为可忽略的 token。错误经 st.first_err 传递 (worker 在 finish 内写入,
// 单网络线程无竞争)。对照 boost asio experimental::channel 文档示例。
using ResultCh = boost::asio::experimental::channel<void(boost::system::error_code, int)>;

struct PeerSetup {
  ed2k::peer::C2CConnection conn;
  std::vector<bool> fs_parts;
  std::uint16_t source_udp_port = 0;   // 源通告的 UDP 端口; 0=未通告/纯 eDonkey (供 Task 4 reask 寻址)
};

static boost::asio::awaitable<tl::expected<PeerSetup,std::error_code>>
setup_source_phase(boost::asio::any_io_executor ex,
                   const ed2k::peer::PeerIdentity& source,
                   std::optional<ed2k::peer::C2CConnection> pre_conn,
                   std::vector<bool> pre_parts,
                   std::uint16_t pre_udp_port,
                   const FileHash& hash,
                   std::uint64_t size,
                   std::chrono::milliseconds timeout,
                   std::optional<std::reference_wrapper<ed2k::server::ServerConnection>> server_conn,
                   std::optional<std::reference_wrapper<ed2k::peer::InboundListener>> listener,
                   std::shared_ptr<const infra::IPFilter> ip_filter,
                   std::uint8_t ip_filter_level,
                   ed2k::peer::ObfuscationPolicy obfuscation_policy,
                   std::optional<UserHash> local_user_hash) {
  if(pre_conn.has_value()){
    // 复用 setup 连接 (已 HELLO+EMULEINFO+SETREQFILEID; 多 part 还含 HASHSETREQUEST); 直接进
    // REQUESTFILENAME。udp_port 沿用 fetch_hashset 阶段已捕获的值, 不重新握手。
    co_return PeerSetup{std::move(*pre_conn), std::move(pre_parts), pre_udp_port};
  }

  bool accepted = false;
  std::optional<ed2k::peer::C2CConnection> conn_opt;
  if(source.endpoint.low_id()){
    if(!server_conn || !listener) co_return tl::unexpected(make_error_code(errc::connect_failed));
    auto cb = co_await server_conn->get().callback_request(source.endpoint.id, timeout);
    if(!cb) co_return tl::unexpected(cb.error());
    auto acc = co_await listener->get().accept_peer(local_user_hash, obfuscation_policy, timeout,
                                                     ip_filter, ip_filter_level);
    if(!acc) co_return tl::unexpected(acc.error());
    conn_opt.emplace(std::move(*acc));
    accepted = true;
  } else {
    ed2k::peer::C2CConnection c(ex);
    c.set_ip_filter(ip_filter, ip_filter_level);
    auto cr = co_await c.connect(source, obfuscation_policy, timeout);
    if(!cr) co_return tl::unexpected(cr.error());
    conn_opt.emplace(std::move(c));
    accepted = false;
  }

  tl::expected<ed2k::peer::C2CHandshakeResult,std::error_code> hr;
  if(accepted) hr = co_await conn_opt->handshake_acceptor_with_mule_info(
      default_hello(obfuscation_policy, local_user_hash), default_mule_info(), timeout);
  else         hr = co_await conn_opt->handshake_with_mule_info(
      default_hello(obfuscation_policy, local_user_hash), default_mule_info(), timeout);
  if(!hr) co_return tl::unexpected(hr.error());
  auto fs = co_await conn_opt->request_file(hash, timeout);
  if(!fs) co_return tl::unexpected(fs.error());
  // 单 part 文件跳过 hashset (aMule 不应答); 多 part 文件仍请求 (mock 序列要求, 结果丢弃)。
  if(size > PART_SIZE){
    auto hs = co_await conn_opt->request_hashset(hash, timeout);
    if(!hs) co_return tl::unexpected(hs.error());
  }
  co_return PeerSetup{std::move(*conn_opt), std::move(fs->parts), hr->mule_info.udp_port};
}

static boost::asio::awaitable<bool>
negotiate_aich_phase(ed2k::peer::C2CConnection& conn,
                     SharedState& st,
                     std::chrono::milliseconds timeout) {
  // M4c: AICH master-hash 协商 + 降级 (per-worker)。匹配才启用两级 verify_block;
  // 不匹配/不支持 AICH → 降级无 AICH 下载 (part-hash MD4 仍兜底)。
  if(!st.aich.has_value()) co_return false;
  auto mh = co_await conn.request_aich_master_hash(st.hash, timeout);
  co_return mh && *mh == *st.aich;
}

static boost::asio::awaitable<tl::expected<void,std::error_code>>
pull_blocks_phase(ed2k::peer::C2CConnection& conn,
                  SharedState& st,
                  std::vector<bool> fs_parts,
                  bool aich_active,
                  std::chrono::milliseconds timeout,
                  std::size_t max_retries) {
  // servable = 对端可服务 part 集合 (初始 = FILESTATUS), 空响应时收缩 (防部分 part 死循环)。
  std::vector<bool> servable = normalize_file_status_parts(std::move(fs_parts), st.size);
  bool large_file = st.size > (std::uint64_t(1) << 32);
  std::size_t retry = 0;
  while(!st.alloc.complete()){
    if(st.complete) break;
    if(st.stopped()) co_return tl::unexpected(make_error_code(errc::cancelled));
    auto nb = st.alloc.next_block_for_parts(servable);
    if(!nb){
      // 无对端可服务块 = 源耗尽。若已完成 → 成功退出; 仅剩我一人且未完成 → io_error;
      // 否则正常退出, 余块由兄弟 worker 处理。
      if(st.complete) co_return tl::expected<void,std::error_code>{};
      if(st.active_workers <= 1) co_return tl::unexpected(make_error_code(errc::io_error));
      co_return tl::expected<void,std::error_code>{};
    }
    auto [part_index, block_in_part, start_byte, end_byte] = *nb;

    std::vector<ed2k::peer::Block> blocks;
    if(large_file){
      auto r = co_await conn.request_blocks_i64(st.hash,
        std::array<std::uint64_t,3>{start_byte,0,0}, std::array<std::uint64_t,3>{end_byte,0,0}, timeout);
      if(!r){ st.alloc.requeue_block(part_index, block_in_part); co_return tl::unexpected(r.error()); }
      blocks = std::move(*r);
    } else {
      auto r = co_await conn.request_blocks(st.hash,
        std::array<std::uint32_t,3>{static_cast<std::uint32_t>(start_byte),0,0},
        std::array<std::uint32_t,3>{static_cast<std::uint32_t>(end_byte),0,0}, timeout);
      if(!r){ st.alloc.requeue_block(part_index, block_in_part); co_return tl::unexpected(r.error()); }
      blocks = std::move(*r);
    }
    if(blocks.empty()){
      // 对端声称有该 part 但未供块 (部分 part) → 标该 part 不可服务 + requeue, 试别块。
      servable[part_index] = false;
      st.alloc.requeue_block(part_index, block_in_part);
      continue;
    }

    for(auto& b : blocks){
      // C2 先验证后写入: AICH 启用时先拉 proof + verify_block, 通过才写盘;
      // 校验失败 requeue 同源重试, 超 max_retries 返回 block_corrupt 让该源退出 (块回队列, 他源可取)。
      if(aich_active){
        auto rd = co_await conn.request_aich_proof(st.hash, *st.aich,
                                                   static_cast<std::uint16_t>(part_index), timeout);
        // 架构决策#4 (review 修复): 等 AICH proof 期间也可能中途收到 QUEUERANKING——
        // request_aich_proof 内部走 pump_until, 对 QUEUERANKING 早已映射为 errc::upload_queued
        // (c2c_connection.cpp pump_until)。与下方 request_blocks(_i64) 分支同款: 原样传播该错误
        // 给 peer_worker 的循环回 queue_wait_phase 重新排队, 而不是落入下面"校验失败"分支当作
        // 数据损坏计入 max_retries——否则会在重试耗尽后误判为 block_corrupt 放弃该源。
        if(!rd && rd.error() == make_error_code(errc::upload_queued)){
          st.alloc.requeue_block(part_index, block_in_part);
          co_return tl::unexpected(rd.error());
        }
        bool ok = false;
        if(rd) ok = st.checker->verify_block(part_index, block_in_part, b.data,
                                             std::span<const ed2k::peer::AICHProofHash>(rd->hashes));
        if(!ok){
          st.alloc.requeue_block(part_index, block_in_part);
          if(++retry > max_retries) co_return tl::unexpected(make_error_code(errc::block_corrupt));
          break;   // 同源重下该块 (next_block_for_parts 会再取到 requeue 的块或下一可服务块)
        }
      }
      auto w = co_await st.pf.write_block_async(b.start, b.end, b.data, st.disk_ex);
      if(!w){ st.alloc.requeue_block(part_index, block_in_part); co_return tl::unexpected(w.error()); }
      st.add_progress(b.end - b.start);
      if(st.alloc.mark_block_done(part_index, block_in_part)){ st.mark_complete(); break; }
      retry = 0;   // 成功一块, 重置同源重试计数
    }
  }
  co_return tl::expected<void,std::error_code>{};
}

// P0 架构决策#3: 排队等待循环。start_upload/accumulate_blocks/AICH proof 等待中途都可能得到
// UploadQueued/errc::upload_queued(见 c2c_connection.cpp 的 accumulate_blocks 中途降级, 与本文件
// pull_blocks_phase AICH 分支对 request_aich_proof 的同款传播, 均属架构决策#4)——本函数
// 统一处理"保持 TCP 连接、等到真正被接受(或彻底放弃)为止"这一段。
//
// 每轮循环并发等待两类事件之一(architecture decision #3 的"TWO events"): (a) TCP 帧: 用
// conn.wait_upload_outcome(kReaskInterval) 等到下一个 ACCEPTUPLOADREQ/新 QUEUERANKING/错误,
// 或干等满 kReaskInterval 收不到任何东西(超时)。(b) 若 (a) 超时且源通告了 UDP 端口
// (source_udp_port!=0), 串行化(架构决策#1, 经 ReaskGate)发起一次 reask_source, 同时不放弃 TCP
// 监听——用 awaitable_operators 的 || 竞速"继续等 TCP"和"这次 reask", 让 ACCEPTUPLOADREQ 若恰好
// 在 reask 往返期间到达也能被立刻捕捉; reask 自身的预算(kReaskCallTimeout)严格小于竞速中 TCP
// 侧的预算(kReaskCallTimeout+kReaskRaceMargin), 故 TCP 分支只可能因为"真收到帧"胜出, 不会因自己
// 的超时抢先吃掉 reask 的结果(见 kReaskRaceMargin 注释)。source_udp_port==0(纯 eDonkey 对端/
// mule 扩展协商失败, 见 Task 2)时无法探活, 只能纯被动继续等 TCP。
//
// 存活总上限 kQueueWaitMax(架构决策#2 第③层)独立于 per-op 快超时, 每当任何 inbound(新排名/
// reask 有响应)到来就刷新——只有连接真正沉默/死掉才会触发, 返回 errc::timed_out。
// st.stop/取消在每轮循环边界检查(与既有 pull_blocks_phase/run_task 的协作式取消模型一致, 见
// download.cpp/session.cpp 现有 st.stopped() 用法), 返回 errc::cancelled(不是 timed_out)。
//
// 退出条件汇总: ACCEPTUPLOADREQ → 成功返回(调用方转下载); QUEUEFULL(TCP 侧或 reask 侧) →
// 放弃该源(errc::upload_queued, 瞬时性, Task 6 可重试); kQueueWaitMax 耗尽 → errc::timed_out;
// st.stop/取消 → errc::cancelled; 连接层面真实错误(如 connection_closed) → 原样放弃该源。
static boost::asio::awaitable<tl::expected<void,std::error_code>>
queue_wait_phase(ed2k::peer::C2CConnection& conn, SharedState& st,
                 std::uint16_t source_udp_port, IPv4 source_ip) {
  using namespace boost::asio::experimental::awaitable_operators;
  using clock_type = std::chrono::steady_clock;
  auto liveness_deadline = clock_type::now() + kQueueWaitMax;
  const auto reask_ep = boost::asio::ip::udp::endpoint(
      boost::asio::ip::address_v4(source_ip.host()), source_udp_port);

  // 分类一次 UploadOutcome 结果: Accepted → 有定论(成功); Queued → 刷新存活期, 无定论(继续等);
  // 错误且为 timed_out → 无定论(本轮静默, 交给调用方决定下一步); 其它错误 → 有定论(放弃该源)。
  auto classify = [&](tl::expected<ed2k::peer::UploadOutcome,std::error_code>& outcome)
      -> std::optional<tl::expected<void,std::error_code>> {
    if(!outcome){
      if(outcome.error() == make_error_code(errc::timed_out)) return std::nullopt;
      return tl::unexpected(outcome.error());
    }
    if(std::holds_alternative<ed2k::peer::UploadAccepted>(*outcome))
      return tl::expected<void,std::error_code>{};
    liveness_deadline = clock_type::now() + kQueueWaitMax;   // Queued: 收到新排名, 刷新存活期
    return std::nullopt;
  };

  for(;;){
    if(st.stopped()) co_return tl::unexpected(make_error_code(errc::cancelled));
    if(clock_type::now() >= liveness_deadline) co_return tl::unexpected(make_error_code(errc::timed_out));

    auto tcp_result = co_await conn.wait_upload_outcome(peer::kReaskInterval);
    if(auto done = classify(tcp_result)) co_return *done;
    if(tcp_result) continue;                 // Queued(已刷新存活期): 直接下一轮, 不必 reask
    // 走到这里 = 本轮 kReaskInterval 内 TCP 静默无新帧(tcp_result 持有 timed_out)。
    if(source_udp_port == 0) continue;        // 纯 TCP 被动: 无法探活, 只能继续等下一个 kReaskInterval

    auto guard = co_await reask_gate_acquire(st.reask_gate);   // 架构决策#1: 串行化
    auto race = co_await (conn.wait_upload_outcome(kReaskCallTimeout + kReaskRaceMargin)
                       || peer::reask_source(st.reask_sock, reask_ep, st.hash, kReaskCallTimeout));
    (void)guard;   // 仅靠析构释放令牌, 变量本身不再读取

    if(race.index() == 0){
      auto& tcp2 = std::get<0>(race);
      if(auto done = classify(tcp2)) co_return *done;
      continue;   // Queued(已刷新)或理论不可达的 timed_out(见上方竞速预算注释)——继续下一轮
    }
    auto& reask_outcome = std::get<1>(race);
    if(std::holds_alternative<peer::ReaskRank>(reask_outcome)){
      liveness_deadline = clock_type::now() + kQueueWaitMax;   // 收到 REASKACK: 刷新存活期
      continue;
    }
    if(std::holds_alternative<peer::ReaskQueueFull>(reask_outcome))
      co_return tl::unexpected(make_error_code(errc::upload_queued));   // 队列已满: 放弃该源
    // ReaskUnavailable: 非致命, 未证实源仍存活, 不刷新存活期, 继续被动等待。
  }
}

// 单次"已建立连接"会话(Task 6 从原 peer_worker 抽出): start_upload → (若 Queued, 排队等待直到
// 被接受或放弃, 见 queue_wait_phase) → AICH master 协商 (per-worker) → 按 next_block_for_parts
// (has_part) 取块 (仅请求对端有该 part 的块) → request_blocks → AICH verify (若启用) →
// write_block → mark_done; 若中途被源重新打回排队(errc::upload_queued, 架构决策#4), 回到排队
// 等待循环而不是判该源失败。返回"这次连接尝试"的最终结果——成功(含"文件已被其它源下完, 我这
// 份工作无需再做"这种和平退出)或失败错误码。抽出后, peer_worker 的外层重连重试循环(Task 6)
// 只需要在每次尝试前调用 setup_source_phase(全新连接)+ 本函数, 不必复制一份控制流。
static boost::asio::awaitable<tl::expected<void,std::error_code>>
run_source_session(ed2k::peer::C2CConnection& conn, SharedState& st, std::vector<bool> fs_parts,
                   std::uint16_t source_udp_port, IPv4 source_ip,
                   std::chrono::milliseconds timeout, std::size_t max_retries){
  auto upload = co_await start_upload_phase(conn, st.hash, timeout);
  if(!upload) co_return tl::unexpected(upload.error());
  if(std::holds_alternative<peer::UploadQueued>(*upload)){
    auto waited = co_await queue_wait_phase(conn, st, source_udp_port, source_ip);
    if(!waited) co_return tl::unexpected(waited.error());
  }

  const bool aich_active = co_await negotiate_aich_phase(conn, st, timeout);
  for(;;){
    // fs_parts 不 move: 中途被打回排队后, 循环回来还要再用同一份初始 FILESTATUS 位图重新构建
    // servable(见 pull_blocks_phase 内 normalize_file_status_parts); 值拷贝成本低(bool 位图)。
    auto pulled = co_await pull_blocks_phase(conn, st, fs_parts, aich_active, timeout, max_retries);
    if(pulled) co_return tl::expected<void,std::error_code>{};
    if(pulled.error() != make_error_code(errc::upload_queued)) co_return tl::unexpected(pulled.error());
    // 中途被源打回排队 (架构决策#4, accumulate_blocks 新识别的信号): 回排队等待循环而非直接放弃
    // 该源。此路径未解出具体新排名(保持 accumulate_blocks 改动最小化), queue_wait_phase 不需要
    // 排名输入, 无影响。
    auto requeued = co_await queue_wait_phase(conn, st, source_udp_port, source_ip);
    if(!requeued) co_return tl::unexpected(requeued.error());
    // 重新被接受: 循环回去继续 pull_blocks_phase(同一连接/文件, aich_active 不变无需重新协商)。
  }
}

// raccoon worker(Task 6 扩展): 连接 source → (复用 setup 连接或全新连接) → run_source_session。
// 一次尝试失败后先分类(is_transient): transient 且重连预算未耗尽 → 退避(cancellable_wait, 可被
// 取消/整文件已完成提前打断)后对同一源发起全新连接重试(不复用旧连接/pre_conn——旧连接大概率
// 已死, pre_conn 只在最初一次真正有效); terminal, 或 transient 但预算已耗尽(kMaxSourceReconnect,
// 计数约定见该常量注释) → 彻底放弃该源。彻底放弃且原因是 transient(重试耗尽而非从未重试过)时,
// 把源记入 st.transient_retry_pool——供 source_reask_supervisor 在下一个周期重新尝试(全新的
// peer_worker 调用, 拿到全新的重连预算)。源耗尽(无对端可服务块)或成功 → finish 退出; 整文件
// 完成由 st.complete 判定 (最后一块 mark_done 置位)。
static boost::asio::awaitable<void>
peer_worker(boost::asio::any_io_executor ex,
            ed2k::peer::PeerIdentity source,   // 按值: 协程帧独立持有, 跨自身所有挂起点(重连退避)有效
            std::optional<ed2k::peer::C2CConnection> pre_conn,
            std::vector<bool> pre_parts,
            std::uint16_t pre_udp_port,
            SharedState& st,
            std::chrono::milliseconds timeout, std::size_t max_retries,
            std::optional<std::reference_wrapper<ed2k::server::ServerConnection>> server_conn,
            std::optional<std::reference_wrapper<ed2k::peer::InboundListener>> listener,
            std::shared_ptr<const infra::IPFilter> ip_filter,
            std::uint8_t ip_filter_level,
            ed2k::peer::ObfuscationPolicy obfuscation_policy,
            std::optional<UserHash> local_user_hash,
            std::chrono::milliseconds reconnect_backoff,
            ResultCh& done_ch){
  auto finish = [&](std::error_code ec){
    st.set_error(ec);        // 首个失败错误 (单网络线程 → 无竞争)
    st.dec_active_workers();
    done_ch.try_send(boost::system::error_code{}, 0);   // capacity 足够大, 永不阻塞; 纯完成信号
  };

  const IPv4 source_ip = IPv4::from_wire(source.endpoint.id);
  std::optional<ed2k::peer::C2CConnection> conn_for_attempt = std::move(pre_conn);
  std::vector<bool> parts_for_attempt = std::move(pre_parts);
  std::uint16_t udp_port_for_attempt = pre_udp_port;
  std::size_t reconnects = 0;

  for(;;){
    auto setup = co_await setup_source_phase(ex, source, std::move(conn_for_attempt), std::move(parts_for_attempt),
                                             udp_port_for_attempt, st.hash, st.size, timeout, server_conn, listener,
                                             ip_filter, ip_filter_level, obfuscation_policy, local_user_hash);
    tl::expected<void,std::error_code> result;
    if(setup){
      result = co_await run_source_session(setup->conn, st, setup->fs_parts, setup->source_udp_port,
                                           source_ip, timeout, max_retries);
    } else {
      result = tl::unexpected(setup.error());
    }
    if(result){ finish(std::error_code{}); co_return; }

    const auto ec = result.error();
    if(st.stopped()){ finish(make_error_code(errc::cancelled)); co_return; }
    const bool can_retry = is_transient(ec) && reconnects < kMaxSourceReconnect;
    if(!can_retry){
      if(is_transient(ec)) st.transient_retry_pool.push_back(source);   // 供监督后续重试
      finish(ec);
      co_return;
    }
    ++reconnects;
    co_await cancellable_wait(st, ex, reconnect_backoff);
    if(st.stopped()){ finish(make_error_code(errc::cancelled)); co_return; }
    if(st.alloc.complete()){ finish(std::error_code{}); co_return; }   // 退避期间他源已下完整文件
    conn_for_attempt.reset(); parts_for_attempt.clear(); udp_port_for_attempt = 0;
  }
}

// Task 6: spawn_worker/source_reask_supervisor 共用的"整次下载不变"配置打包。MultiSourceDownload
// ::Impl 是私有嵌套类型(仅类自身与友元 Builder 可见), 本文件里的自由函数不能直接引用它——沿用
// 本文件既有惯例(fetch_hashset/setup_source_phase/peer_worker 均以摊平字段传参, 而非传 Impl&),
// 用这个小结构体收敛 Task 6 新增两处调用点(spawn_worker/source_reask_supervisor)的公共字段,
// 不改动既有函数签名。全部字段按值持有(shared_ptr/optional<reference_wrapper> 拷贝代价低)。
struct WorkerContext {
  boost::asio::any_io_executor ex;
  std::optional<std::reference_wrapper<ed2k::server::ServerConnection>> server_conn;
  std::optional<std::reference_wrapper<ed2k::peer::InboundListener>> listener;
  std::shared_ptr<const infra::IPFilter> ip_filter;
  std::uint8_t ip_filter_level;
  ed2k::peer::ObfuscationPolicy obfuscation_policy;
  std::optional<UserHash> local_user_hash;
};

// 启动一个新的 peer_worker(Task 6): 递增 active_workers 后 co_spawn, 供 run() 的初始批次与
// source_reask_supervisor 的新源/重试源共用, 避免重复"递增计数 + co_spawn"样板。pre_conn/
// pre_parts/pre_udp_port 默认空——仅 run() 里复用 setup 阶段连接的那一个源会传实参。
static void
spawn_worker(const WorkerContext& wc, const ed2k::peer::PeerIdentity& source, SharedState& st,
            std::chrono::milliseconds timeout, std::size_t max_retries,
            std::chrono::milliseconds reconnect_backoff, ResultCh& done_ch,
            std::optional<ed2k::peer::C2CConnection> pre_conn = std::nullopt,
            std::vector<bool> pre_parts = {}, std::uint16_t pre_udp_port = 0){
  ++st.active_workers;
  boost::asio::co_spawn(wc.ex,
    peer_worker(wc.ex, source, std::move(pre_conn), std::move(pre_parts), pre_udp_port, st,
                timeout, max_retries, wc.server_conn, wc.listener,
                wc.ip_filter, wc.ip_filter_level, wc.obfuscation_policy,
                wc.local_user_hash, reconnect_backoff, done_ch),
    boost::asio::detached);
}

// 编排监督(Task 6): 下载存活期间周期性重新 get_sources, 合并未知新源 + 重试已弃的 transient 源;
// 直到 st.stopped()(取消/shutdown)或 st.alloc.complete()(整文件已被下完)。只有 run() 探测到
// server_conn 有值(即有办法查更多源)才会启动本协程——没有服务器连接 = 结构性无法重问, 行为与
// Task 6 之前完全一致(见 run() 内的启动条件), 不影响任何未注入 server_conn 的既有调用方/测试。
//
// 复用既有 get_sources 机制(server_conn->get().get_sources, 与 run_task/download_link 现有的
// 首次取源调用完全同一套 API)——本任务不改"问哪个服务器"(Task 7 范围), 只在其结果之上叠加
// 周期重问 + 合并 + 重试的编排框架, Task 7 更换服务器来源后本框架不需要改动。
//
// 去重复用既有 same_source(id+port), 与 run() 开头 Kad 增源分支同一套判定; ip_filter 判定同理。
// known_sources 即 run() 的 self.sources(单网络线程写入, 无并发)。
static boost::asio::awaitable<void>
source_reask_supervisor(WorkerContext wc, SharedState& st,
                        std::vector<ed2k::peer::PeerIdentity>& known_sources,
                        std::chrono::milliseconds timeout, std::size_t max_retries,
                        std::chrono::milliseconds reask_interval,
                        std::chrono::milliseconds reconnect_backoff,
                        ResultCh& done_ch){
  std::size_t empty_cycles = 0;   // 连续"无源可用"空转轮数(Task 6 review 修复 Important#1)
  for(;;){
    co_await cancellable_wait(st, wc.ex, reask_interval);
    if(st.stopped() || st.alloc.complete()) break;
    if(!wc.server_conn) break;   // 防御性: run() 只在有值时才会启动本协程, 正常不会走到这里

    std::size_t spawned_this_cycle = 0;   // 本轮实际增补(新源 + 重试源)的 worker 数
    auto found = co_await wc.server_conn->get().get_sources(st.hash, st.size, timeout);
    if(st.stopped() || st.alloc.complete()) break;
    if(found){
      for(const auto& src : found->sources){
        if(wc.ip_filter && wc.ip_filter->blocked(IPv4::from_wire(src.id), wc.ip_filter_level)) continue;
        const bool known = std::any_of(known_sources.begin(), known_sources.end(),
                                       [&](const peer::PeerIdentity& cur){ return same_source(cur.endpoint, src); });
        if(known) continue;
        peer::PeerIdentity identity{src, std::nullopt};
        known_sources.push_back(identity);
        spawn_worker(wc, identity, st, timeout, max_retries, reconnect_backoff, done_ch);
        ++spawned_this_cycle;
      }
    }
    // get_sources 失败(服务器连接问题等)不致命: 忽略本轮合并, 下个周期继续尝试(eMule 惯例——
    // 服务器暂时联系不上也不放弃下载; 是否需要重连服务器本身属于 Task 7 的服务器选择范围)。

    if(!st.transient_retry_pool.empty()){
      // 重试已弃的 transient 源: 取走当前池并清空(新 peer_worker 调用拿到全新重连预算)。
      auto retry_pool = std::move(st.transient_retry_pool);
      st.transient_retry_pool.clear();
      for(auto& identity : retry_pool){
        spawn_worker(wc, identity, st, timeout, max_retries, reconnect_backoff, done_ch);
        ++spawned_this_cycle;
      }
    }

    // Important#1 修复: "无源可用"有界放弃(阈值/理由见 kMaxEmptyReaskCycles 注释)。本轮既没增补
    // 任何 worker、当前也无活跃 worker → 源已耗尽且服务器/重试池都补不上, 记一轮空转; 连续达到
    // 上限即退出监督, 交由 run() 收尾以源耗尽错误返回。任一进展(增补了 worker 或仍有活跃 worker)
    // 清零重来——给晚到的源机会但有界。
    if(spawned_this_cycle == 0 && st.active_workers == 0){
      if(++empty_cycles >= kMaxEmptyReaskCycles) break;
    } else {
      empty_cycles = 0;
    }
  }
  st.supervisor_active = false;
  done_ch.try_send(boost::system::error_code{}, 0);
}

boost::asio::awaitable<tl::expected<void,std::error_code>>
MultiSourceDownload::run(std::chrono::milliseconds total_timeout,
                         std::size_t max_retries,
                         std::chrono::milliseconds source_reask_interval,
                         std::chrono::milliseconds source_reconnect_backoff){
  auto& self = *impl_;
  // B4: peers 由调用方显式传入(self.kad_peers), 不再从 kad_network 自己的路由表取——
  // kad_network 常见是调用方新建的 ephemeral 实例(独立 socket, 不与常驻 Kad 读者抢包,
  // 见 Session::run_task 的用法), 其自身路由表从始至终为空, routing_table().closest_to(...)
  // 恒返回空。真正的候选 peers 来自"主"路由表的快照, 由调用方(如 Session::run_task 从
  // self->kad 快照, 或测试直接构造)通过 Builder::kad_peers() 注入。kad_peers 为空时(未启用
  // Kad, 或主路由表当前没有可用联系人)整段跳过, 行为等同"仅服务器源"(不回归既有路径)。
  if(self.kad_network && !self.kad_peers.empty()){
    auto& kad_network = self.kad_network->get();
    const auto file_id = kad_id_from_hash(self.hash);
    auto kad_sources = co_await kad_network.find_sources(self.kad_peers, file_id, self.size, total_timeout);
    if(kad_sources){
      for(const auto& entry : *kad_sources){
        auto identity = peer_identity_from_kad_source(entry);
        if(!identity) continue;
        if(self.ip_filter && self.ip_filter->blocked(
            IPv4::from_wire(identity->endpoint.id), self.ip_filter_level)) continue;
        const auto duplicate = std::any_of(self.sources.begin(), self.sources.end(),
                                           [&](const peer::PeerIdentity& current){
                                             return same_source(current.endpoint, identity->endpoint);
                                           });
        if(!duplicate) self.sources.push_back(std::move(*identity));
      }
    }
  }

  // 阶段一: setup — 顺序从首个可用源拿 hashset (失败顺次尝试下一源), 连接复用给该源 worker。
  FetchResult fr;
  std::size_t setup_idx = 0;
  std::error_code setup_err = make_error_code(errc::connect_failed);
  for(; setup_idx < self.sources.size(); ++setup_idx){
    if(self.stop && *self.stop) co_return tl::unexpected(make_error_code(errc::cancelled));
    auto r = co_await fetch_hashset(self.ex, self.sources[setup_idx], self.hash, self.size, total_timeout,
                                    self.server_conn, self.listener, self.ip_filter, self.ip_filter_level,
                                    self.obfuscation_policy, self.local_user_hash);
    if(r){ fr = std::move(*r); break; }
    setup_err = r.error();
  }
  if(setup_idx == self.sources.size()) co_return tl::unexpected(setup_err);

  // 共享状态 (仅网络线程访问 → 无锁)。pf 为空 (M1 不接 .part.met); alloc 从 pf 恢复 (全 pending)。
  PartFile pf(self.out, self.size, self.hash, fr.part_hashes);
  // 断点续传恢复值: size 减去 pf 剩余 gap 总长度 = 已完成字节数 (全新下载 gaps 覆盖全文件, 结果为 0)。
  std::uint64_t initial_done = self.size;
  for(const auto& [gs, ge] : pf.gaps()) initial_done -= (ge - gs);
  BlockAllocator alloc(self.size, fr.part_hashes, self.aich, pf);
  std::size_t n_workers = self.sources.size() - setup_idx;
  SharedState st{std::move(pf), std::move(alloc), std::nullopt, self.aich, self.hash, self.size,
                 self.disk_ex, net::UdpSocket(self.ex), ReaskGate(self.ex, 1),
                 false, /*active_workers=*/0, std::nullopt};
  // 聚合初始化后补显式赋值: SharedState 尾部含 NDEBUG 条件成员, 位置初始化脆弱, 显式赋值更安全。
  // active_workers 从 0 开始, 由下面 spawn_worker 逐个递增(Task 6: 与 source_reask_supervisor
  // 动态增补 worker 时递增的方式统一, 不再在此处一次性赋值 n_workers)。
  st.bytes_done = initial_done;
  st.on_progress = self.on_progress;
  st.stop = self.stop;
  st.reask_gate.try_send(boost::system::error_code{});   // 初始塞一个令牌: 门闸起始态="空闲可用"
  if(st.on_progress) st.on_progress(st.bytes_done, st.size);   // 初始进度(续传时非 0)
  if(self.aich) st.checker.emplace(*self.aich, self.size);

  // 阶段二: raccoon — N worker 并发。worker[setup_idx] 复用 setup 连接, 其余全新连接。Task 6:
  // 之后 source_reask_supervisor 可能动态增补更多 worker, done_ch 容量按上限预留充分余量
  // (GETSOURCES 单次应答受协议 u8 计数上限 255, 加上初始批次与 transient 重试池, 1024 足够宽松;
  // try_send 是非阻塞的 fire-and-forget, 容量不足会静默丢 token 导致 run() 的收尾等待永久挂起,
  // 故宁可预留充分)。
  WorkerContext wc{self.ex, self.server_conn, self.listener, self.ip_filter, self.ip_filter_level,
                   self.obfuscation_policy, self.local_user_hash};
  ResultCh done_ch(self.ex, n_workers + kDoneChannelHeadroom);
  for(std::size_t i = setup_idx; i < self.sources.size(); ++i){
    if(i == setup_idx){
      spawn_worker(wc, self.sources[i], st, total_timeout, max_retries, source_reconnect_backoff, done_ch,
                  std::move(fr.conn), std::move(fr.fs_parts), fr.source_udp_port);
    } else {
      spawn_worker(wc, self.sources[i], st, total_timeout, max_retries, source_reconnect_backoff, done_ch);
    }
  }

  // Task 6: 只有存在服务器连接(有办法查更多源)才启动周期重问监督; 无服务器连接(如多数既有
  // 单测/直接构造场景)时行为与 Task 6 之前完全一致——不启动监督, 下方收尾等待循环退化为原来的
  // "等到 active_workers 归零"。supervisor_active 必须在 co_spawn 之前同步置位(而非等协程自己
  // 跑到才置位), 避免下方收尾循环在监督协程真正开始执行前就误判"没有监督在跑"而提前退出。
  if(self.server_conn){
    st.supervisor_active = true;
    boost::asio::co_spawn(self.ex,
      source_reask_supervisor(wc, st, self.sources, total_timeout, max_retries,
                              source_reask_interval, source_reconnect_backoff, done_ch),
      boost::asio::detached);
  }

  // 收尾等待: 按状态驱动(而非固定计数), 因为 supervisor 可能动态增补新 worker(active_workers
  // 因此可能回升)。只要还有活跃 worker 或 supervisor 未退出, 就必须继续等待收完成信号——否则
  // 它们持有的 SharedState& 会在本函数返回、st 析构后变成悬垂引用(worker/supervisor 各自退出前
  // 的最后一步都是 try_send 一个 token, 因此每次能让本循环条件变化的状态转移都配对一次 token,
  // 不会永久卡在 async_receive 上; 详见 worker finish()/supervisor 收尾处注释)。
  // 结果判定沿用既有逻辑: complete 优先于 stopped, 其次上报 first_err(worker 里记录的首个错误)。
  while(st.active_workers > 0 || st.supervisor_active){
    (void)co_await done_ch.async_receive(boost::asio::use_awaitable);
  }
  if(st.alloc.complete()) co_return tl::expected<void,std::error_code>{};
  if(st.stopped()) co_return tl::unexpected(make_error_code(errc::cancelled));
  co_return tl::unexpected(st.first_err.value_or(make_error_code(errc::io_error)));
}

} // namespace ed2k::download
