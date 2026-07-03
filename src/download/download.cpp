#include "ed2k/download/download.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/download/block_allocator.hpp"
#include "ed2k/download/aich_checker.hpp"
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/util/error.hpp"
#include <atomic>
namespace ed2k::download {
Download::Download(boost::asio::any_io_executor ex, const std::filesystem::path& out,
                   const FileHash& hash, std::uint64_t size, const ed2k::server::SourceEndpoint& source)
  : conn_(ex), out_(out), hash_(hash), size_(size), source_(source) {}

boost::asio::awaitable<tl::expected<void,std::error_code>>
Download::run(std::chrono::milliseconds timeout){
  IPv4 ip{source_.id};
  auto cr = co_await conn_.connect(ip, source_.port, timeout);
  if(!cr) co_return tl::unexpected(cr.error());
  ed2k::peer::HelloInfo mine; mine.nickname = "ed2k"; mine.version = 0x3C;
  auto hr = co_await conn_.handshake(mine, timeout);
  if(!hr) co_return tl::unexpected(hr.error());
  auto fs = co_await conn_.request_file(hash_, timeout);
  if(!fs) co_return tl::unexpected(fs.error());
  auto hs = co_await conn_.request_hashset(hash_, timeout);
  if(!hs) co_return tl::unexpected(hs.error());
  PartFile pf(out_, size_, hash_, std::move(*hs));
  (void)co_await conn_.request_filename(hash_, timeout);   // 文件名可选,忽略失败
  auto up = co_await conn_.start_upload(hash_, timeout);
  if(!up) co_return tl::unexpected(up.error());
  auto missing = pf.missing_parts_peer_has(fs->parts);
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
  : ex_(ex), out_(out), hash_(hash), size_(size), aich_(aich),
    sources_(std::move(sources)), server_conn_(server_conn), listener_(listener) {}

// 单源 worker:连接 source,握手+拉 hashset,初始化 BlockAllocator(从 PartFile 恢复),
// 按 BlockAllocator 分配的 AICH 小块逐块请求。
// AICH 启用时:先向 peer 请求 proof,verify_block 校验通过才 write_block(先验证后写入)。
// 校验失败:requeue + 同源重试,超过 max_retries 返回 block_corrupt 让 MultiSourceDownload 切源。
// 连接阶段按 source.low_id() 分支(M3):
//   LowID(+server_conn+listener): callback_request -> listener.accept -> C2CConnection(socket&&)
//   LowID(缺 server_conn/listener): 防御性 connect_failed(M2 已 filter 掉 LowID)
//   HighID: 直连 conn.connect(IPv4{source.id}, source.port) —— 现状不变
static boost::asio::awaitable<tl::expected<void,std::error_code>>
peer_worker(boost::asio::any_io_executor ex,
            const std::filesystem::path& out,
            const FileHash& hash, std::uint64_t size,
            const std::optional<AICHHash>& aich,
            const ed2k::server::SourceEndpoint& source,
            std::chrono::milliseconds timeout,
            std::size_t max_retries,
            ed2k::server::ServerConnection* server_conn,
            ed2k::peer::InboundListener* listener){
  bool accepted = false;   // LowID 回调路径下我方是 TCP acceptor,握手角色随之翻转
  std::optional<ed2k::peer::C2CConnection> conn_opt;
  if(source.low_id()){
    if(!server_conn || !listener) co_return tl::unexpected(make_error_code(errc::connect_failed));
    auto cb = co_await server_conn->callback_request(source.id, timeout);
    if(!cb) co_return tl::unexpected(cb.error());
    auto acc = co_await listener->accept(timeout);
    if(!acc) co_return tl::unexpected(acc.error());
    conn_opt.emplace(std::move(*acc));
    accepted = true;
  } else {
    ed2k::peer::C2CConnection c(ex);
    auto cr = co_await c.connect(IPv4{source.id}, source.port, timeout);
    if(!cr) co_return tl::unexpected(cr.error());
    conn_opt.emplace(std::move(c));
    accepted = false;
  }
  auto& conn = *conn_opt;
  ed2k::peer::HelloInfo mine; mine.nickname = "ed2k"; mine.version = 0x3C;
  // 握手角色:acceptor(我方接收 HELLO 再回 HELLOANSWER) vs initiator(我方先发 HELLO)。
  // 不用 co_await 三目运算(parser-fragile),显式 if/else;HighID 路径与改前逐字节一致。
  tl::expected<ed2k::peer::HelloInfo,std::error_code> hr;
  if(accepted) hr = co_await conn.handshake_acceptor(mine, timeout);
  else         hr = co_await conn.handshake(mine, timeout);
  if(!hr) co_return tl::unexpected(hr.error());
  auto fs = co_await conn.request_file(hash, timeout);
  if(!fs) co_return tl::unexpected(fs.error());
  auto hs = co_await conn.request_hashset(hash, timeout);
  if(!hs) co_return tl::unexpected(hs.error());

  // 用真实 part hashes 打开 PartFile（构造时即校验已存在的 part 实现续传）
  PartFile pf(out, size, hash, *hs);
  // 从 PartFile 已有块状态恢复 BlockAllocator:已完成的块不入 pending 队列
  BlockAllocator alloc{size, *hs, aich, pf};
  std::optional<AICHChecker> checker;
  bool aich_active = false;
  // part_index 在线协议为 u16 (FILESTATUS part 计数即 u16, ≤65535 part≈580TiB) —— 自然有界,
  // 旧 flat 块索引的 num_blocks<=65535 守卫已删 (G10)。M4 per-part 块不跨 part, 叶序与两级树一致。
  if(aich.has_value()){
    checker.emplace(*aich, size);
    aich_active = true;
  }

  (void)co_await conn.request_filename(hash, timeout);   // 可选,忽略
  auto up = co_await conn.start_upload(hash, timeout);
  if(!up) co_return tl::unexpected(up.error());

  // per-part 块分解(M4): next_block 返回 (part_index, block_in_part, start, end), 块绝不跨 part。
  // start = part_index*PART_SIZE + block_in_part*AICH_BLOCK_SIZE, end 按 part 边界截断。
  bool large_file = size > (std::uint64_t(1) << 32);
  std::size_t retry = 0;
  while(!alloc.complete()){
    auto nb = alloc.next_block();
    if(!nb.has_value()) break;
    auto [part_index, block_in_part, start_byte, end_byte] = *nb;

    std::vector<ed2k::peer::Block> blocks;
    if(large_file){
      auto r = co_await conn.request_blocks_i64(hash,
        std::array<std::uint64_t,3>{start_byte,0,0}, std::array<std::uint64_t,3>{end_byte,0,0}, timeout);
      if(!r) co_return tl::unexpected(r.error());
      blocks = std::move(*r);
    } else {
      auto r = co_await conn.request_blocks(hash,
        std::array<std::uint32_t,3>{static_cast<std::uint32_t>(start_byte),0,0},
        std::array<std::uint32_t,3>{static_cast<std::uint32_t>(end_byte),0,0}, timeout);
      if(!r) co_return tl::unexpected(r.error());
      blocks = std::move(*r);
    }
    if(blocks.empty()) co_return tl::unexpected(make_error_code(errc::io_error));

    for(auto& b : blocks){
      // C2 先验证后写入:AICH 启用时,先拉 proof + verify_block,通过才写盘;
      // 校验失败 requeue 同源重试,超过 max_retries 返回 block_corrupt 让上层切源。
      if(aich_active){
        // M4a: request_aich_proof 发真实 u16 part_index (不再用 flat global 占位)。
        //   verify_block 仍用 M2 签名 (block_index=part-major 叶序, data, span<Digest>):
        //   block_index = Σ blocks_in_part(p) for p<part_index + block_in_part。
        //   M4b 改签名 verify_block(part_index, block_in_part, data, span<AICHProofHash>) + 标识符重建,
        //   届时去掉 leaf 折算与 flat 哈希提取。3 个 AICH 下载用例仍 DISABLED 待 M4b/M4c。
        auto rd = co_await conn.request_aich_proof(hash, *aich, static_cast<std::uint16_t>(part_index), timeout);
        std::vector<std::array<std::byte,20>> proofs;
        if(rd) for(const auto& p : rd->hashes) proofs.push_back(p.hash);
        std::size_t leaf = block_in_part;
        for(std::size_t p=0; p<part_index; ++p){
          std::uint64_t ps = std::min(PART_SIZE, size - static_cast<std::uint64_t>(p)*PART_SIZE);
          leaf += static_cast<std::size_t>((ps + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE);
        }
        bool ok = rd.has_value() && checker->verify_block(leaf, b.data, proofs);
        if(!ok){
          alloc.requeue_block(part_index, block_in_part);
          if(++retry > max_retries) co_return tl::unexpected(make_error_code(errc::block_corrupt));
          break;   // 同源重下该块(重新 next_block 会取到 requeue 的块或下一块)
        }
      }
      auto w = pf.write_block(b.start, b.end, b.data);
      if(!w) co_return tl::unexpected(w.error());
      alloc.mark_block_done(part_index, block_in_part);
      retry = 0;   // 成功一块,重置同源重试计数
    }
  }

  if(!alloc.complete()) co_return tl::unexpected(make_error_code(errc::io_error));
  co_return tl::expected<void,std::error_code>{};
}

boost::asio::awaitable<tl::expected<void,std::error_code>>
MultiSourceDownload::run(std::chrono::milliseconds total_timeout,
                         std::size_t max_retries){
  // MVP：顺序尝试每个 source，第一个成功的 source 完成整文件块级下载。
  // 多源并发编排（raccoon 算法）留待后续：需要跨 source 共享 BlockAllocator
  // 状态与异步并发 worker，单线程 io_context 下用 condition_variable 会死锁。
  std::error_code last_err = make_error_code(errc::connect_failed);
  for(const auto& source : sources_){
    auto r = co_await peer_worker(ex_, out_, hash_, size_, aich_, source, total_timeout, max_retries,
                                  server_conn_, listener_);
    if(r.has_value()) co_return tl::expected<void,std::error_code>{};
    last_err = r.error();
    // 失败则尝试下一个 source
  }
  co_return tl::unexpected(last_err);
}

} // namespace ed2k::download
