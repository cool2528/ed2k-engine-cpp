#include "net/inflate.hpp"
#include "ed2k/util/error.hpp"
#include <zlib.h>
namespace ed2k::net {
tl::expected<std::vector<std::byte>,std::error_code>
zlib_inflate(std::span<const std::byte> in, std::size_t max_out){
  z_stream zs{};
  if(inflateInit(&zs) != Z_OK) return tl::unexpected(make_error_code(errc::decompress_failed));
  zs.next_in  = reinterpret_cast<Bytef*>(const_cast<std::byte*>(in.data()));
  zs.avail_in = static_cast<uInt>(in.size());
  std::vector<std::byte> out;
  std::byte buf[16384];
  int ret;
  do {
    zs.next_out  = reinterpret_cast<Bytef*>(buf);
    zs.avail_out = sizeof buf;
    ret = inflate(&zs, Z_NO_FLUSH);
    if(ret != Z_OK && ret != Z_STREAM_END){ inflateEnd(&zs); return tl::unexpected(make_error_code(errc::decompress_failed)); }
    std::size_t produced = sizeof buf - zs.avail_out;
    if(out.size() + produced > max_out){ inflateEnd(&zs); return tl::unexpected(make_error_code(errc::decompress_failed)); }
    out.insert(out.end(), buf, buf + produced);
  } while(ret != Z_STREAM_END);
  inflateEnd(&zs);
  return out;
}
}
