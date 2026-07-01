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
  for(std::uint32_t p : missing){
    // 按 AICH 块(180KiB)逐块请求:整 part 9.72MiB 超过 8MiB 帧上限,无法单包传输。
    // 每块写入后由 PartFile 增量累计,part 组装完整时回读做 MD4 校验。
    std::uint64_t pstart = static_cast<std::uint64_t>(p) * PART_SIZE;
    std::uint64_t pend = std::min((static_cast<std::uint64_t>(p)+1)*PART_SIZE, size_);
    for(std::uint64_t cur = pstart; cur < pend; ){
      std::uint64_t end = std::min(cur + AICH_BLOCK_SIZE, pend);
      auto blocks = co_await conn_.request_blocks(hash_,
        std::array<std::uint32_t,3>{static_cast<std::uint32_t>(cur),0,0},
        std::array<std::uint32_t,3>{static_cast<std::uint32_t>(end),0,0},
        timeout);
      if(!blocks) co_return tl::unexpected(blocks.error());
      if(blocks->empty()) co_return tl::unexpected(make_error_code(errc::io_error));   // 避免空响应死循环
      for(auto& b : *blocks){
        auto w = pf.write_block(static_cast<std::uint32_t>(b.start),
                                static_cast<std::uint32_t>(b.end), b.data);
        if(!w) co_return tl::unexpected(w.error());
        cur = b.end;   // 按实际回送块推进
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
                                          std::vector<server::SourceEndpoint> sources)
  : ex_(ex), out_(out), hash_(hash), size_(size), aich_(aich), sources_(std::move(sources)) {}

// 单源 worker:连接 source,握手+拉 hashset,初始化 BlockAllocator(从 PartFile 恢复),
// 按 BlockAllocator 分配的 AICH 小块逐块请求。
// AICH 启用时:先向 peer 请求 proof,verify_block 校验通过才 write_block(先验证后写入)。
// 校验失败:requeue + 同源重试,超过 max_retries 返回 block_corrupt 让 MultiSourceDownload 切源。
static boost::asio::awaitable<tl::expected<void,std::error_code>>
peer_worker(boost::asio::any_io_executor ex,
            const std::filesystem::path& out,
            const FileHash& hash, std::uint64_t size,
            const std::optional<AICHHash>& aich,
            const ed2k::server::SourceEndpoint& source,
            std::chrono::milliseconds timeout,
            std::size_t max_retries){
  ed2k::peer::C2CConnection conn(ex);
  IPv4 ip{source.id};
  auto cr = co_await conn.connect(ip, source.port, timeout);
  if(!cr) co_return tl::unexpected(cr.error());
  ed2k::peer::HelloInfo mine; mine.nickname = "ed2k"; mine.version = 0x3C;
  auto hr = co_await conn.handshake(mine, timeout);
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
  std::size_t num_blocks = static_cast<std::size_t>((size + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE);
  bool aich_active = false;
  // u16 block_index 容量上限:超过 65535 块(~11.5GB)时降级为 part-MD4-only
  if(aich.has_value() && num_blocks <= 65535){
    checker.emplace(*aich, num_blocks);
    aich_active = true;
  }

  (void)co_await conn.request_filename(hash, timeout);   // 可选,忽略
  auto up = co_await conn.start_upload(hash, timeout);
  if(!up) co_return tl::unexpected(up.error());

  // PART_SIZE(9728000) 不是 AICH_BLOCK_SIZE(184320) 的整数倍(≈52.78),
  // 故 global_block_index 不能用 start_byte/AICH_BLOCK_SIZE, 必须用 pi*blocks_per_part+ai。
  // blocks_per_part = ceil(PART_SIZE / AICH_BLOCK_SIZE) = 53 (第 53 块短,143360 字节)。
  constexpr std::size_t blocks_per_part = (PART_SIZE + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;
  bool large_file = size > (std::uint64_t(1) << 32);
  std::size_t retry = 0;
  while(!alloc.complete()){
    auto nb = alloc.next_block();
    if(!nb.has_value()) break;
    auto [pi, ai, start_byte, end_byte] = *nb;

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
        std::size_t global = pi * blocks_per_part + ai;
        auto proof = co_await conn.request_aich_proof(hash, static_cast<std::uint16_t>(global), timeout);
        bool ok = proof.has_value() && checker->verify_block(global, b.data, *proof);
        if(!ok){
          alloc.requeue_block(pi, ai);
          if(++retry > max_retries) co_return tl::unexpected(make_error_code(errc::block_corrupt));
          break;   // 同源重下该块(重新 next_block 会取到 requeue 的块或下一块)
        }
      }
      auto w = pf.write_block(static_cast<std::uint32_t>(b.start),
                              static_cast<std::uint32_t>(b.end), b.data);
      if(!w) co_return tl::unexpected(w.error());
      alloc.mark_block_done(pi, ai);
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
    auto r = co_await peer_worker(ex_, out_, hash_, size_, aich_, source, total_timeout, max_retries);
    if(r.has_value()) co_return tl::expected<void,std::error_code>{};
    last_err = r.error();
    // 失败则尝试下一个 source
  }
  co_return tl::unexpected(last_err);
}

} // namespace ed2k::download
