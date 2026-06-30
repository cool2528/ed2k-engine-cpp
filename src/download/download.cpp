#include "ed2k/download/download.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/util/error.hpp"
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
    std::uint32_t start = static_cast<std::uint32_t>(p * PART_SIZE);
    std::uint32_t end = static_cast<std::uint32_t>(std::min((p+1)*PART_SIZE, size_));
    auto blocks = co_await conn_.request_blocks(hash_, {start,0,0}, {end,0,0}, timeout);
    if(!blocks) co_return tl::unexpected(blocks.error());
    for(auto& b : *blocks){
      auto w = pf.write_block(b.start, b.end, b.data);
      if(!w) co_return tl::unexpected(w.error());
    }
  }
  if(!pf.complete()) co_return tl::unexpected(make_error_code(errc::io_error));
  co_return tl::expected<void,std::error_code>{};
}
}
