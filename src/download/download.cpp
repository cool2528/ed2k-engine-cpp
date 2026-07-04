#include "ed2k/download/download.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/download/block_allocator.hpp"
#include "ed2k/download/aich_checker.hpp"
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
Download::Download(boost::asio::any_io_executor ex, const std::filesystem::path& out,
                   const FileHash& hash, std::uint64_t size, const ed2k::server::SourceEndpoint& source)
  : conn_(ex), out_(out), hash_(hash), size_(size), source_(source) {}

boost::asio::awaitable<tl::expected<void,std::error_code>>
Download::run(std::chrono::milliseconds timeout){
  IPv4 ip = IPv4::from_wire(source_.id);
  auto cr = co_await conn_.connect(ip, source_.port, timeout);
  if(!cr) co_return tl::unexpected(cr.error());
  ed2k::peer::HelloInfo mine;
  mine.user_hash = *ed2k::UserHash::from_hex("0123456789abcdeffedcba9876543210");
  mine.nickname = "ed2k"; mine.version = 0x3C; mine.port = 4662;
  auto hr = co_await conn_.handshake(mine, timeout);
  if(!hr) co_return tl::unexpected(hr.error());
  auto fs = co_await conn_.request_file(hash_, timeout);
  if(!fs) co_return tl::unexpected(fs.error());
  // 单 part 文件跳过 hashset (aMule 不应答); 传空 part_hashes, PartFile 自合成 {file_hash}。
  std::vector<PartHash> part_hashes;
  if(size_ > PART_SIZE){
    auto hs = co_await conn_.request_hashset(hash_, timeout);
    if(!hs) co_return tl::unexpected(hs.error());
    part_hashes = std::move(*hs);
  }
  PartFile pf(out_, size_, hash_, std::move(part_hashes));
  (void)co_await conn_.request_filename(hash_, timeout);   // 文件名可选,忽略失败
  auto up = co_await conn_.start_upload(hash_, timeout);
  if(!up) co_return tl::unexpected(up.error());
  // aMule 对完整共享文件发 FILESTATUS count=0 (无 part 位图): ClientTCPSocket.cpp OP_SETREQFILEID
  // 处理 `if(reqfile->IsPartFile()) WritePartStatus else WriteUInt16(0)`。语义 = 对端拥有整文件
  // (所有 part 可用), 不是 "0 part"。故 fs->parts 空 (count=0) 时视为全部 part 可用;
  // 非空 (PartFile 不完整源发真实位图) 按位图过滤。单 part 文件 num_parts=1, 同此规则覆盖。
  std::vector<bool> peer_parts = fs->parts;
  if(peer_parts.empty()){
    peer_parts.assign(static_cast<std::size_t>((size_ + PART_SIZE - 1) / PART_SIZE), true);
  }
  auto missing = pf.missing_parts_peer_has(peer_parts);
  // 缺失 part 位图: 用于跳过对端没有 / 已完成的 part。
  std::vector<bool> need_part(static_cast<std::size_t>((size_ + PART_SIZE - 1) / PART_SIZE), false);
  for(std::uint32_t p : missing) need_part[p] = true;
  // per-part 块迭代: 块绝不跨 part 边界, 与 aMule 两级树 per-part 叶序一致。
  std::size_t np = static_cast<std::size_t>((size_ + PART_SIZE - 1) / PART_SIZE);
  for(std::size_t p=0; p<np; ++p){
    if(p >= need_part.size() || !need_part[p]) continue;
    std::uint64_t pstart = static_cast<std::uint64_t>(p) * PART_SIZE;
    std::uint64_t plen = std::min(PART_SIZE, size_ - pstart);
    std::size_t nb = static_cast<std::size_t>((plen + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE);
    for(std::size_t b=0; b<nb; ++b){
      if(pf.is_block_done(p, b)) continue;
      std::uint64_t start = pstart + static_cast<std::uint64_t>(b) * AICH_BLOCK_SIZE;
      std::uint64_t end = std::min(start + AICH_BLOCK_SIZE, pstart + plen);
      auto blocks = co_await conn_.request_blocks(hash_,
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
  if(!pf.complete()) co_return tl::unexpected(make_error_code(errc::io_error));
  co_return tl::expected<void,std::error_code>{};
}

MultiSourceDownload::MultiSourceDownload(boost::asio::any_io_executor ex,
                                          const std::filesystem::path& out,
                                          const FileHash& hash, std::uint64_t size,
                                          const std::optional<AICHHash>& aich,
                                          std::vector<server::SourceEndpoint> sources,
                                          server::ServerConnection* server_conn,
                                          peer::InboundListener* listener)
  : ex_(ex), disk_ex_(ex), out_(out), hash_(hash), size_(size), aich_(aich),
    sources_(std::move(sources)),
    server_conn_(server_conn ? std::optional<std::reference_wrapper<server::ServerConnection>>(std::ref(*server_conn)) : std::nullopt),
    listener_(listener ? std::optional<std::reference_wrapper<peer::InboundListener>>(std::ref(*listener)) : std::nullopt) {}

MultiSourceDownload MultiSourceDownload::Builder::build() {
  return MultiSourceDownload(net_ex_, disk_ex_, std::move(out_), hash_, size_,
                             std::move(aich_), std::move(sources_),
                             std::move(server_), std::move(listener_));
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
              const ed2k::server::SourceEndpoint& source, const FileHash& hash,
              std::uint64_t size,
              std::chrono::milliseconds timeout,
              std::optional<std::reference_wrapper<ed2k::server::ServerConnection>> server_conn,
              std::optional<std::reference_wrapper<ed2k::peer::InboundListener>> listener){
  bool accepted = false;   // LowID 回调路径下我方是 TCP acceptor, 握手角色随之翻转
  std::optional<ed2k::peer::C2CConnection> conn_opt;
  if(source.low_id()){
    if(!server_conn || !listener) co_return tl::unexpected(make_error_code(errc::connect_failed));
    auto cb = co_await server_conn->get().callback_request(source.id, timeout);
    if(!cb) co_return tl::unexpected(cb.error());
    auto acc = co_await listener->get().accept(timeout);
    if(!acc) co_return tl::unexpected(acc.error());
    conn_opt.emplace(std::move(*acc));
    accepted = true;
  } else {
    ed2k::peer::C2CConnection c(ex);
    auto cr = co_await c.connect(IPv4::from_wire(source.id), source.port, timeout);
    if(!cr) co_return tl::unexpected(cr.error());
    conn_opt.emplace(std::move(c));
    accepted = false;
  }
  ed2k::peer::HelloInfo mine;
  mine.user_hash = *ed2k::UserHash::from_hex("0123456789abcdeffedcba9876543210");
  mine.nickname = "ed2k"; mine.version = 0x3C; mine.port = 4662;
  tl::expected<ed2k::peer::HelloInfo,std::error_code> hr;
  if(accepted) hr = co_await conn_opt->handshake_acceptor(mine, timeout);
  else         hr = co_await conn_opt->handshake(mine, timeout);
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

// raccoon worker: 连接 source → (复用 setup 连接或全新连接) → start_upload → AICH master
// 协商 (per-worker) → 按 next_block_for_parts(has_part) 取块 (仅请求对端有该 part 的块) →
// request_blocks → AICH verify (若启用) → write_block → mark_done。源耗尽 (无对端可服务块)
// 或失败 → finally_send 退出; 整文件完成由 st.complete 判定 (最后一块 mark_done 置位)。
static boost::asio::awaitable<void>
peer_worker(boost::asio::any_io_executor ex,
            const ed2k::server::SourceEndpoint& source,
            std::optional<ed2k::peer::C2CConnection> pre_conn,
            std::vector<bool> pre_parts,
            SharedState& st,
            std::chrono::milliseconds timeout, std::size_t max_retries,
            std::optional<std::reference_wrapper<ed2k::server::ServerConnection>> server_conn,
            std::optional<std::reference_wrapper<ed2k::peer::InboundListener>> listener,
            ResultCh& done_ch){
  auto finish = [&](std::error_code ec){
    st.set_error(ec);        // 首个失败错误 (单网络线程 → 无竞争)
    st.dec_active_workers();
    done_ch.try_send(boost::system::error_code{}, 0);   // capacity=N, 永不阻塞; 纯完成信号
  };

  std::optional<ed2k::peer::C2CConnection> conn_opt;
  std::vector<bool> fs_parts;
  if(pre_conn.has_value()){
    // 复用 setup 连接 (已 HELLO+SETREQFILEID; 多 part 还含 HASHSETREQUEST); 直接进 REQUESTFILENAME。
    conn_opt = std::move(pre_conn);
    fs_parts = std::move(pre_parts);
  } else {
    // 全新连接: connect + handshake + request_file (+ request_hashset 仅多 part; 共享 st 已有 hashset, 丢弃)
    bool accepted = false;
    if(source.low_id()){
      if(!server_conn || !listener){ finish(make_error_code(errc::connect_failed)); co_return; }
      auto cb = co_await server_conn->get().callback_request(source.id, timeout);
      if(!cb){ finish(cb.error()); co_return; }
      auto acc = co_await listener->get().accept(timeout);
      if(!acc){ finish(acc.error()); co_return; }
      conn_opt.emplace(std::move(*acc));
      accepted = true;
    } else {
      ed2k::peer::C2CConnection c(ex);
      auto cr = co_await c.connect(IPv4::from_wire(source.id), source.port, timeout);
      if(!cr){ finish(cr.error()); co_return; }
      conn_opt.emplace(std::move(c));
      accepted = false;
    }
    ed2k::peer::HelloInfo mine;
    mine.user_hash = *ed2k::UserHash::from_hex("0123456789abcdeffedcba9876543210");
    mine.nickname = "ed2k"; mine.version = 0x3C; mine.port = 4662;
    tl::expected<ed2k::peer::HelloInfo,std::error_code> hr;
    if(accepted) hr = co_await conn_opt->handshake_acceptor(mine, timeout);
    else         hr = co_await conn_opt->handshake(mine, timeout);
    if(!hr){ finish(hr.error()); co_return; }
    auto fs = co_await conn_opt->request_file(st.hash, timeout);
    if(!fs){ finish(fs.error()); co_return; }
    fs_parts = std::move(fs->parts);
    // 单 part 文件跳过 hashset (aMule 不应答); 多 part 文件仍请求 (mock 序列要求, 结果丢弃)。
    if(st.size > PART_SIZE){
      auto hs = co_await conn_opt->request_hashset(st.hash, timeout);
      if(!hs){ finish(hs.error()); co_return; }
    }
  }
  auto& conn = *conn_opt;

  (void)co_await conn.request_filename(st.hash, timeout);   // 文件名可选, 忽略失败
  auto up = co_await conn.start_upload(st.hash, timeout);
  if(!up){ finish(up.error()); co_return; }

  // M4c: AICH master-hash 协商 + 降级 (per-worker)。匹配才启用两级 verify_block;
  // 不匹配/不支持 AICH → 降级无 AICH 下载 (part-hash MD4 仍兜底)。
  bool aich_active = false;
  if(st.aich.has_value()){
    auto mh = co_await conn.request_aich_master_hash(st.hash, timeout);
    if(mh && *mh == *st.aich) aich_active = true;
  }

  // servable = 对端可服务 part 集合 (初始 = FILESTATUS), 空响应时收缩 (防部分 part 死循环)。
  std::vector<bool> servable = fs_parts;
  // aMule 完整共享文件 FILESTATUS count=0 (无位图, 见 ClientTCPSocket.cpp OP_SETREQFILEID:
  // !IsPartFile() → WriteUInt16(0)) = 拥有整文件 → 空位图视为全部 part 可服务。
  // 非空位图 (PartFile 不完整源) 按实际 have-part 过滤。
  if(servable.empty()){
    servable.assign(static_cast<std::size_t>((st.size + PART_SIZE - 1) / PART_SIZE), true);
  }
  bool large_file = st.size > (std::uint64_t(1) << 32);
  std::size_t retry = 0;
  while(!st.alloc.complete()){
    if(st.complete) break;
    auto nb = st.alloc.next_block_for_parts(servable);
    if(!nb){
      // 无对端可服务块 = 源耗尽。若已完成 → 成功退出; 仅剩我一人且未完成 → io_error;
      // 否则正常退出, 余块由兄弟 worker 处理。
      if(st.complete){ finish({}); co_return; }
      if(st.active_workers <= 1){ finish(make_error_code(errc::io_error)); co_return; }
      finish({}); co_return;
    }
    auto [part_index, block_in_part, start_byte, end_byte] = *nb;

    std::vector<ed2k::peer::Block> blocks;
    if(large_file){
      auto r = co_await conn.request_blocks_i64(st.hash,
        std::array<std::uint64_t,3>{start_byte,0,0}, std::array<std::uint64_t,3>{end_byte,0,0}, timeout);
      if(!r){ st.alloc.requeue_block(part_index, block_in_part); finish(r.error()); co_return; }
      blocks = std::move(*r);
    } else {
      auto r = co_await conn.request_blocks(st.hash,
        std::array<std::uint32_t,3>{static_cast<std::uint32_t>(start_byte),0,0},
        std::array<std::uint32_t,3>{static_cast<std::uint32_t>(end_byte),0,0}, timeout);
      if(!r){ st.alloc.requeue_block(part_index, block_in_part); finish(r.error()); co_return; }
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
          if(++retry > max_retries){ finish(make_error_code(errc::block_corrupt)); co_return; }
          break;   // 同源重下该块 (next_block_for_parts 会再取到 requeue 的块或下一可服务块)
        }
      }
      auto w = co_await st.pf.write_block_async(b.start, b.end, b.data, st.disk_ex);
      if(!w){ st.alloc.requeue_block(part_index, block_in_part); finish(w.error()); co_return; }
      if(st.alloc.mark_block_done(part_index, block_in_part)){ st.mark_complete(); break; }
      retry = 0;   // 成功一块, 重置同源重试计数
    }
  }
  finish({});
}

boost::asio::awaitable<tl::expected<void,std::error_code>>
MultiSourceDownload::run(std::chrono::milliseconds total_timeout,
                         std::size_t max_retries){
  // 阶段一: setup — 顺序从首个可用源拿 hashset (失败顺次尝试下一源), 连接复用给该源 worker。
  FetchResult fr;
  std::size_t setup_idx = 0;
  std::error_code setup_err = make_error_code(errc::connect_failed);
  for(; setup_idx < sources_.size(); ++setup_idx){
    auto r = co_await fetch_hashset(ex_, sources_[setup_idx], hash_, size_, total_timeout,
                                    server_conn_, listener_);
    if(r){ fr = std::move(*r); break; }
    setup_err = r.error();
  }
  if(setup_idx == sources_.size()) co_return tl::unexpected(setup_err);

  // 共享状态 (仅网络线程访问 → 无锁)。pf 为空 (M1 不接 .part.met); alloc 从 pf 恢复 (全 pending)。
  PartFile pf(out_, size_, hash_, fr.part_hashes);
  BlockAllocator alloc(size_, fr.part_hashes, aich_, pf);
  std::size_t n_workers = sources_.size() - setup_idx;
  SharedState st{std::move(pf), std::move(alloc), std::nullopt, aich_, hash_, size_,
                 disk_ex_, false, n_workers, std::nullopt};
  if(aich_) st.checker.emplace(*aich_, size_);

  // 阶段二: raccoon — N worker 并发。worker[setup_idx] 复用 setup 连接, 其余全新连接。
  ResultCh done_ch(ex_, n_workers);      // capacity = N
  for(std::size_t i = setup_idx; i < sources_.size(); ++i){
    std::optional<ed2k::peer::C2CConnection> pre_conn;
    std::vector<bool> pre_parts;
    if(i == setup_idx){ pre_conn = std::move(fr.conn); pre_parts = std::move(fr.fs_parts); }
    boost::asio::co_spawn(ex_,
      peer_worker(ex_, sources_[i], std::move(pre_conn), std::move(pre_parts), st,
                  total_timeout, max_retries, server_conn_, listener_, done_ch),
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
