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

// 单源 worker：连接一个 source，握手 + 拉取 hashset，初始化 BlockAllocator，
// 然后按 BlockAllocator 分配的 AICH 小块逐块请求并写入 PartFile。
// 失败时返回错误码（多源版本可继续尝试下一个 source）。
static boost::asio::awaitable<tl::expected<void,std::error_code>>
peer_worker(boost::asio::any_io_executor ex,
            const std::filesystem::path& out,
            const FileHash& hash, std::uint64_t size,
            const std::optional<AICHHash>& aich,
            const ed2k::server::SourceEndpoint& source,
            std::chrono::milliseconds timeout){
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
  // 用真实 part hashes 初始化 BlockAllocator
  BlockAllocator alloc{size, *hs, aich};
  std::optional<AICHChecker> checker;
  if(aich.has_value()){
    std::size_t num_blocks = static_cast<std::size_t>((size + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE);
    checker.emplace(*aich, num_blocks);
  }

  (void)co_await conn.request_filename(hash, timeout);   // 可选,忽略
  auto up = co_await conn.start_upload(hash, timeout);
  if(!up) co_return tl::unexpected(up.error());

  bool large_file = size > (std::uint64_t(1) << 32);
  while(!alloc.complete()){
    auto nb = alloc.next_block();
    if(!nb.has_value()) break;
    auto [pi, ai, start_byte, end_byte] = *nb;
    (void)pi; (void)ai;

    std::vector<ed2k::peer::Block> blocks;
    if(large_file){
      std::array<std::uint64_t,3> starts{start_byte,0,0};
      std::array<std::uint64_t,3> ends{end_byte,0,0};
      auto r = co_await conn.request_blocks_i64(hash, starts, ends, timeout);
      if(!r) co_return tl::unexpected(r.error());
      blocks = std::move(*r);
    } else {
      std::array<std::uint32_t,3> starts{static_cast<std::uint32_t>(start_byte),0,0};
      std::array<std::uint32_t,3> ends{static_cast<std::uint32_t>(end_byte),0,0};
      auto r = co_await conn.request_blocks(hash, starts, ends, timeout);
      if(!r) co_return tl::unexpected(r.error());
      blocks = std::move(*r);
    }

    for(auto& b : blocks){
      // 块级写入：write_block 只在整 part 写齐时做 MD4 校验；
      // 块级增量写入不会被校验为 corrupt，AICH 校验由 checker 负责（若有 root hash）。
      auto w = pf.write_block(static_cast<std::uint32_t>(b.start),
                              static_cast<std::uint32_t>(b.end), b.data);
      if(!w) co_return tl::unexpected(w.error());
      alloc.mark_block_done(pi, ai);
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
  (void)max_retries;
  std::error_code last_err = make_error_code(errc::connect_failed);
  for(const auto& source : sources_){
    auto r = co_await peer_worker(ex_, out_, hash_, size_, aich_, source, total_timeout);
    if(r.has_value()) co_return tl::expected<void,std::error_code>{};
    last_err = r.error();
    // 失败则尝试下一个 source
  }
  co_return tl::unexpected(last_err);
}

} // namespace ed2k::download
