#include "ed2k/download/download.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/download/block_allocator.hpp"
#include "ed2k/download/aich_checker.hpp"
#include "ed2k/kad/network.hpp"
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/util/error.hpp"
#include <optional>
#include <cassert>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
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

boost::asio::awaitable<tl::expected<void,std::error_code>>
start_upload_phase(peer::C2CConnection& conn,
                   const FileHash& hash,
                   std::chrono::milliseconds timeout) {
  (void)co_await conn.request_filename(hash, timeout);   // 文件名可选,忽略失败
  auto up = co_await conn.start_upload(hash, timeout);
  if(!up) co_return tl::unexpected(up.error());
  co_return tl::expected<void,std::error_code>{};
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
  auto hr = co_await conn_.handshake(default_hello(obfuscation_policy_, local_user_hash_), timeout);
  if(!hr) co_return tl::unexpected(hr.error());
  auto setup = co_await fetch_hashset_phase(conn_, hash_, size_, timeout);
  if(!setup) co_return tl::unexpected(setup.error());
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
       std::shared_ptr<const infra::IPFilter> ip_filter_arg,
       std::uint8_t ip_filter_level_arg,
       peer::ObfuscationPolicy obfuscation_policy_arg,
       std::optional<UserHash> local_user_hash_arg,
       ProgressFn on_progress_arg)
    : ex(net_ex), disk_ex(std::move(disk_ex_arg)), out(std::move(out_arg)), hash(hash_arg), size(size_arg),
      aich(std::move(aich_arg)), sources(std::move(sources_arg)),
      server_conn(std::move(server_conn_arg)), listener(std::move(listener_arg)),
      kad_network(std::move(kad_network_arg)), ip_filter(std::move(ip_filter_arg)),
      ip_filter_level(ip_filter_level_arg), obfuscation_policy(obfuscation_policy_arg),
      local_user_hash(std::move(local_user_hash_arg)), on_progress(std::move(on_progress_arg)) {}

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
  std::shared_ptr<const infra::IPFilter> ip_filter;
  std::uint8_t ip_filter_level = 127;
  peer::ObfuscationPolicy obfuscation_policy = peer::ObfuscationPolicy::disabled;
  std::optional<UserHash> local_user_hash;
  ProgressFn on_progress;
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
      std::nullopt, nullptr, 127, peer::ObfuscationPolicy::disabled, std::nullopt, nullptr)) {}

MultiSourceDownload::MultiSourceDownload(boost::asio::any_io_executor net_ex,
                                         boost::asio::any_io_executor disk_ex,
                                         std::filesystem::path out, FileHash hash, std::uint64_t size,
                                         std::optional<AICHHash> aich,
                                         std::vector<peer::PeerIdentity> sources,
                                         std::optional<std::reference_wrapper<server::ServerConnection>> server_conn,
                                         std::optional<std::reference_wrapper<peer::InboundListener>> listener,
                                         std::optional<std::reference_wrapper<kad::KadNetwork>> kad_network,
                                         std::shared_ptr<const infra::IPFilter> ip_filter,
                                         std::uint8_t ip_filter_level,
                                         peer::ObfuscationPolicy obfuscation_policy,
                                         std::optional<UserHash> local_user_hash,
                                         ProgressFn on_progress)
  : impl_(std::make_unique<Impl>(net_ex, std::move(disk_ex), std::move(out), hash, size,
                                 std::move(aich), std::move(sources), std::move(server_conn),
                                 std::move(listener), std::move(kad_network), std::move(ip_filter),
                                 ip_filter_level, obfuscation_policy, std::move(local_user_hash),
                                 std::move(on_progress))) {}

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
                             std::move(kad_network_), std::move(ip_filter_), ip_filter_level_,
                             obfuscation_policy_, std::move(local_user_hash_),
                             std::move(on_progress_));
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
  tl::expected<ed2k::peer::HelloInfo,std::error_code> hr;
  if(accepted) hr = co_await conn_opt->handshake_acceptor(
      default_hello(obfuscation_policy, local_user_hash), timeout);
  else         hr = co_await conn_opt->handshake(
      default_hello(obfuscation_policy, local_user_hash), timeout);
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
  co_return r;
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
  bool complete = false;
  std::size_t active_workers = 0;
  std::optional<std::error_code> first_err;
  std::uint64_t bytes_done = 0;
  ProgressFn on_progress;
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
// 完成信号 channel: worker 退出时 try_send 发一个 token; run() 收 N 个 token。
// 签名 void(boost::system::error_code, int): 首参 error_code 被 use_awaitable 当操作状态
// (始终 success), int 为可忽略的 token。错误经 st.first_err 传递 (worker 在 finish 内写入,
// 单网络线程无竞争)。对照 boost asio experimental::channel 文档示例。
using ResultCh = boost::asio::experimental::channel<void(boost::system::error_code, int)>;

struct PeerSetup {
  ed2k::peer::C2CConnection conn;
  std::vector<bool> fs_parts;
};

static boost::asio::awaitable<tl::expected<PeerSetup,std::error_code>>
setup_source_phase(boost::asio::any_io_executor ex,
                   const ed2k::peer::PeerIdentity& source,
                   std::optional<ed2k::peer::C2CConnection> pre_conn,
                   std::vector<bool> pre_parts,
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
    // 复用 setup 连接 (已 HELLO+SETREQFILEID; 多 part 还含 HASHSETREQUEST); 直接进 REQUESTFILENAME。
    co_return PeerSetup{std::move(*pre_conn), std::move(pre_parts)};
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

  tl::expected<ed2k::peer::HelloInfo,std::error_code> hr;
  if(accepted) hr = co_await conn_opt->handshake_acceptor(
      default_hello(obfuscation_policy, local_user_hash), timeout);
  else         hr = co_await conn_opt->handshake(
      default_hello(obfuscation_policy, local_user_hash), timeout);
  if(!hr) co_return tl::unexpected(hr.error());
  auto fs = co_await conn_opt->request_file(hash, timeout);
  if(!fs) co_return tl::unexpected(fs.error());
  // 单 part 文件跳过 hashset (aMule 不应答); 多 part 文件仍请求 (mock 序列要求, 结果丢弃)。
  if(size > PART_SIZE){
    auto hs = co_await conn_opt->request_hashset(hash, timeout);
    if(!hs) co_return tl::unexpected(hs.error());
  }
  co_return PeerSetup{std::move(*conn_opt), std::move(fs->parts)};
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

// raccoon worker: 连接 source → (复用 setup 连接或全新连接) → start_upload → AICH master
// 协商 (per-worker) → 按 next_block_for_parts(has_part) 取块 (仅请求对端有该 part 的块) →
// request_blocks → AICH verify (若启用) → write_block → mark_done。源耗尽 (无对端可服务块)
// 或失败 → finally_send 退出; 整文件完成由 st.complete 判定 (最后一块 mark_done 置位)。
static boost::asio::awaitable<void>
peer_worker(boost::asio::any_io_executor ex,
            const ed2k::peer::PeerIdentity& source,
            std::optional<ed2k::peer::C2CConnection> pre_conn,
            std::vector<bool> pre_parts,
            SharedState& st,
            std::chrono::milliseconds timeout, std::size_t max_retries,
            std::optional<std::reference_wrapper<ed2k::server::ServerConnection>> server_conn,
            std::optional<std::reference_wrapper<ed2k::peer::InboundListener>> listener,
            std::shared_ptr<const infra::IPFilter> ip_filter,
            std::uint8_t ip_filter_level,
            ed2k::peer::ObfuscationPolicy obfuscation_policy,
            std::optional<UserHash> local_user_hash,
            ResultCh& done_ch){
  auto finish = [&](std::error_code ec){
    st.set_error(ec);        // 首个失败错误 (单网络线程 → 无竞争)
    st.dec_active_workers();
    done_ch.try_send(boost::system::error_code{}, 0);   // capacity=N, 永不阻塞; 纯完成信号
  };

  auto setup = co_await setup_source_phase(ex, source, std::move(pre_conn), std::move(pre_parts),
                                           st.hash, st.size, timeout, server_conn, listener,
                                           std::move(ip_filter), ip_filter_level,
                                           obfuscation_policy, std::move(local_user_hash));
  if(!setup){ finish(setup.error()); co_return; }
  auto upload = co_await start_upload_phase(setup->conn, st.hash, timeout);
  if(!upload){ finish(upload.error()); co_return; }
  const bool aich_active = co_await negotiate_aich_phase(setup->conn, st, timeout);
  auto pulled = co_await pull_blocks_phase(setup->conn, st, std::move(setup->fs_parts),
                                           aich_active, timeout, max_retries);
  finish(pulled ? std::error_code{} : pulled.error());
}

boost::asio::awaitable<tl::expected<void,std::error_code>>
MultiSourceDownload::run(std::chrono::milliseconds total_timeout,
                         std::size_t max_retries){
  auto& self = *impl_;
  if(self.kad_network){
    auto& kad_network = self.kad_network->get();
    const auto file_id = kad_id_from_hash(self.hash);
    auto peers = kad_network.routing_table().closest_to(file_id, kad::KBucket::capacity);
    if(!peers.empty()){
      auto kad_sources = co_await kad_network.find_sources(peers, file_id, self.size, total_timeout);
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
  }

  // 阶段一: setup — 顺序从首个可用源拿 hashset (失败顺次尝试下一源), 连接复用给该源 worker。
  FetchResult fr;
  std::size_t setup_idx = 0;
  std::error_code setup_err = make_error_code(errc::connect_failed);
  for(; setup_idx < self.sources.size(); ++setup_idx){
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
                 self.disk_ex, false, n_workers, std::nullopt};
  // 聚合初始化后补显式赋值: SharedState 尾部含 NDEBUG 条件成员, 位置初始化脆弱, 显式赋值更安全。
  st.bytes_done = initial_done;
  st.on_progress = self.on_progress;
  if(st.on_progress) st.on_progress(st.bytes_done, st.size);   // 初始进度(续传时非 0)
  if(self.aich) st.checker.emplace(*self.aich, self.size);

  // 阶段二: raccoon — N worker 并发。worker[setup_idx] 复用 setup 连接, 其余全新连接。
  ResultCh done_ch(self.ex, n_workers);      // capacity = N
  for(std::size_t i = setup_idx; i < self.sources.size(); ++i){
    std::optional<ed2k::peer::C2CConnection> pre_conn;
    std::vector<bool> pre_parts;
    if(i == setup_idx){ pre_conn = std::move(fr.conn); pre_parts = std::move(fr.fs_parts); }
    boost::asio::co_spawn(self.ex,
      peer_worker(self.ex, self.sources[i], std::move(pre_conn), std::move(pre_parts), st,
                  total_timeout, max_retries, self.server_conn, self.listener,
                  self.ip_filter, self.ip_filter_level, self.obfuscation_policy,
                  self.local_user_hash, done_ch),
      boost::asio::detached);
  }
  // 收集 N 个完成信号 (worker 退出即 try_send; run 挂起在 async_receive, 网络线程跑 worker)。
  // 错误经 st.first_err 传递 (worker 在 finish 内写入, 单网络线程无竞争)。
  for(std::size_t i = 0; i < n_workers; ++i){
    (void)co_await done_ch.async_receive(boost::asio::use_awaitable);
  }
  if(st.alloc.complete()) co_return tl::expected<void,std::error_code>{};
  co_return tl::unexpected(st.first_err.value_or(make_error_code(errc::io_error)));
}

} // namespace ed2k::download
