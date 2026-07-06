#include "ed2k/download/part_file.hpp"
#include "ed2k/metfile/known_part_met.hpp"
#include "crypto/md4.hpp"
#include <algorithm>
#include <fstream>
#include <optional>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/this_coro.hpp>
namespace ed2k::download {
namespace {
std::filesystem::path part_met_path_for(const std::filesystem::path& path) {
  auto met = path;
  met += (path.extension() == ".part") ? ".met" : ".part.met";
  return met;
}
}

struct PartFile::Impl {
  Impl(const std::filesystem::path& path, std::uint64_t size, const FileHash& file_hash,
       std::vector<PartHash> part_hashes);

  bool open_for_write() const noexcept;
  std::vector<std::uint32_t> missing_parts_peer_has(const std::vector<bool>& peer_parts) const;
  tl::expected<void,std::error_code> write_block(std::uint64_t start, std::uint64_t end,
                                                 std::span<const std::byte> data);
  boost::asio::awaitable<tl::expected<void,std::error_code>>
    write_block_async(std::uint64_t start, std::uint64_t end, std::span<const std::byte> data,
                      boost::asio::any_io_executor disk_ex);
  bool is_block_done(std::size_t part, std::size_t block_in_part) const noexcept;
  std::vector<std::pair<std::size_t,std::size_t>> pending_blocks() const;
  bool complete() const noexcept;
  std::vector<std::pair<std::uint64_t,std::uint64_t>> gaps() const;
  tl::expected<ed2k::share::KnownFile,std::error_code> to_known_file() const;

  std::filesystem::path path;
  std::filesystem::path met_path;   // .part outputs use sibling .met; other outputs use .part.met
  std::uint64_t size;
  FileHash file_hash;
  std::vector<PartHash> part_hashes;
  std::vector<bool> part_done;
  std::vector<std::uint64_t> part_filled;  // 每 part 已写入字节数，用于增量组装后触发 MD4 校验
  std::vector<std::vector<bool>> block_done;  // block_done[part][block_in_part]; 块不跨 part 边界
  std::fstream f;

  // 数据 part 数 = ceil(size/PART_SIZE)。aMule GetPartCount() 同此 (块分配/完成判定基准)。
  // part_hashes 可能多 1 (Red 变体: 文件恰为 PART_SIZE 整数倍时 aMule 追加空尾 part MD4(""),
  // 见 ed2k_hasher HashVariant::Red + aMule SendHashsetPacket)。空尾 part 无数据, 不参与块分配/
  // 完成判定, 仅存于 part_hashes 供 hashset/.met 保真。故 num_parts 取 size 而非 hash 计数。
  std::size_t num_parts() const { return (size + PART_SIZE - 1) / PART_SIZE; }
  std::uint64_t part_size(std::size_t part) const {
    std::uint64_t base = static_cast<std::uint64_t>(part) * PART_SIZE;
    if (base >= size) return 0;
    return std::min(PART_SIZE, size - base);
  }
  std::size_t blocks_in_part(std::size_t part) const {
    return static_cast<std::size_t>((part_size(part) + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE);
  }
  // P4c-3 M2: .part.met 续传。met-first 恢复 (避整文件重哈希, D1); 失败/陈旧回退 rehash_all。
  bool try_load_met();           // 解析 .part.met → 恢复 part_done/block_done; 返回是否成功应用
  void rehash_all();             // 回退路径: 逐 part 回读 + MD4 校验 (P4a 原续传逻辑)
  void save_met() const;         // 把当前 gaps() 落盘 .part.met (part 完成时调用)
};

PartFile::Impl::Impl(const std::filesystem::path& path_arg, std::uint64_t size_arg,
                     const FileHash& file_hash_arg, std::vector<PartHash> part_hashes_arg)
  : path(path_arg), met_path(part_met_path_for(path_arg)), size(size_arg),
    file_hash(file_hash_arg), part_hashes(std::move(part_hashes_arg)) {
  if(part_hashes.empty()) part_hashes.push_back(file_hash);
  // 状态向量按数据 part 数 (num_parts) 分配, 非 hash 计数 (Red 变体空尾 part 不占数据 part 槽)。
  const std::size_t np = num_parts();
  part_done.assign(np, false);
  part_filled.assign(np, 0);
  // per-part 块位图: 每 part ceil(part_size/AICH_BLOCK_SIZE) 块, 块不跨 part 边界。
  block_done.resize(np);
  for(std::size_t p=0;p<np;++p)
    block_done[p].assign(blocks_in_part(p), false);
  if(!std::filesystem::exists(path)) { std::ofstream c(path, std::ios::binary); }
  f.open(path, std::ios::binary | std::ios::in | std::ios::out);
  // P4c-3 M2: met-first 续传。.part.met 有效 → 恢复 part_done 无需重哈希 (D1 性能);
  //          缺失/损坏/陈旧 (hash 不匹配) → 回退 rehash_all (P4a 安全网)。
  if(!try_load_met()) rehash_all();
}
// .part.met 解析恢复。仅当 magic 有效且 hash/part_hashes 与本文件一致时应用 (否则视为陈旧)。
// 信任模型: met 标 done 的 part 直接受信 (写盘时已 MD4 校验); 仅以 file_size(data) >= part_end
// 防截断, 不再回读重哈希。partial part (met 中为 gap) → 重下整 part (块级不持久化, 与 P4a 一致)。
bool PartFile::Impl::try_load_met(){
  if(!std::filesystem::exists(met_path)) return false;
  std::ifstream m(met_path, std::ios::binary);
  if(!m.is_open()) return false;
  std::vector<char> raw((std::istreambuf_iterator<char>(m)), std::istreambuf_iterator<char>());
  std::vector<std::byte> buf(raw.size());
  for(std::size_t i=0;i<raw.size();++i) buf[i] = std::byte(static_cast<unsigned char>(raw[i]));
  auto r = ed2k::parse_part_met(buf);
  if(!r) return false;
  if(!(r->hash == file_hash) || r->part_hashes != part_hashes) return false;   // 陈旧 met (异文件)
  if(r->size != 0 && r->size != size) return false;
  std::uint64_t data_sz = std::filesystem::exists(path) ? std::filesystem::file_size(path) : 0;
  for(std::size_t i=0;i<part_done.size();++i){   // 仅数据 part (空尾 part 不在 part_done)
    std::uint64_t pstart = static_cast<std::uint64_t>(i)*PART_SIZE;
    std::uint64_t pend = std::min(static_cast<std::uint64_t>(pstart+PART_SIZE), size);
    bool gap_overlaps = false;
    for(auto& g : r->gaps){
      if(g.first < pend && g.second > pstart){ gap_overlaps = true; break; }
    }
    if(!gap_overlaps && data_sz >= pend){
      part_done[i] = true; part_filled[i] = pend - pstart;
      block_done[i].assign(blocks_in_part(i), true);
    }   // else: 保持 init 的 false (partial/截断 part → 重下)
  }
  return true;
}
// 回退路径 (P4a 原续传): 逐 part 回读 + MD4 校验。met 缺失/损坏/陈旧时使用。
void PartFile::Impl::rehash_all(){
  for(std::size_t i=0;i<part_done.size();++i){   // 仅数据 part (空尾 part 无数据不重哈希)
    std::uint64_t pstart = i*PART_SIZE;
    std::uint64_t pend = std::min((i+1)*PART_SIZE, size);
    std::uint64_t plen = pend-pstart;
    if(plen==0) continue;
    std::vector<std::byte> buf(plen);
    f.seekg(pstart);
    f.read(reinterpret_cast<char*>(buf.data()), plen);
    if(static_cast<std::uint64_t>(f.gcount()) == plen){
      crypto::MD4 m; m.update(buf);
      if(i < part_hashes.size() && PartHash::from_bytes(m.finish()) == part_hashes[i]){
        part_done[i] = true; part_filled[i] = plen;
      }
    }
    f.clear();
  }
  // 推导 per-part block_done: 一个 part 的 MD4 校验通过 → 该 part 所有块均 done。
  for(std::size_t p=0;p<part_done.size();++p){
    if(part_done[p]) block_done[p].assign(blocks_in_part(p), true);
  }
}
// 落盘 .part.met: gaps() 为缺失整 part 区间 (与 part 粒度状态模型一致)。
void PartFile::Impl::save_met() const {
  ed2k::PartFileState st;
  st.hash = file_hash;
  st.part_hashes = part_hashes;
  st.size = size;
  st.gaps = gaps();
  auto bytes = ed2k::write_part_met(st);
  std::ofstream m(met_path, std::ios::binary | std::ios::trunc);
  if(!m.is_open()) return;
  m.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}
bool PartFile::Impl::open_for_write() const noexcept { return f.is_open(); }
std::vector<std::uint32_t> PartFile::Impl::missing_parts_peer_has(const std::vector<bool>& peer_parts) const {
  std::vector<std::uint32_t> out;
  for(std::size_t i=0;i<part_done.size() && i<peer_parts.size();++i)
    if(!part_done[i] && peer_parts[i]) out.push_back(static_cast<std::uint32_t>(i));
  return out;
}
// 写入一个 per-part 块 [start, end)。块绝不跨 part 边界(per-part 模型):
//   part = start/PART_SIZE, block_in_part = (start%PART_SIZE)/AICH_BLOCK_SIZE。
// 一次连续写盘, 然后按 part 边界累计 part_filled (per-part 块恒落单 part, 循环退化为单段),
// 该 part 字节满即回读整 part 做 MD4 校验。part 完成时落盘 .part.met (M2 续传持久化)。
tl::expected<void,std::error_code> PartFile::Impl::write_block(std::uint64_t start, std::uint64_t end, std::span<const std::byte> data){
  std::size_t part = static_cast<std::size_t>(start / PART_SIZE);
  std::size_t bip  = static_cast<std::size_t>((start % PART_SIZE) / AICH_BLOCK_SIZE);
  if(part >= block_done.size() || bip >= block_done[part].size()) return {};
  if(block_done[part][bip]) return {};   // 幂等: 已置位直接成功, 不重复写盘/校验/计数
  f.seekp(start);
  f.write(reinterpret_cast<const char*>(data.data()), data.size());
  block_done[part][bip] = true;
  // 按 part 边界切分 [start, end) 累计 part_filled 并触发 MD4 (per-part 块恒单 part)。
  std::uint64_t cur = start;
  std::uint64_t finish = end;
  while(cur < finish){
    std::size_t p = static_cast<std::size_t>(cur / PART_SIZE);
    if(p >= part_done.size()) break;
    std::uint64_t pstart = static_cast<std::uint64_t>(p) * PART_SIZE;
    std::uint64_t pend = std::min((static_cast<std::uint64_t>(p)+1)*PART_SIZE, size);
    std::uint64_t seg_end = std::min(finish, pend);
    if(!part_done[p]) part_filled[p] += (seg_end - cur);
    cur = seg_end;
    // 该 part 字节满: 回读整 part 做 MD4 校验
    if(!part_done[p] && part_filled[p] == (pend - pstart)){
      std::vector<std::byte> buf(pend - pstart);
      f.flush();
      f.seekg(pstart);
      f.read(reinterpret_cast<char*>(buf.data()), pend - pstart);
      f.clear();
      if(static_cast<std::uint64_t>(f.gcount()) != (pend - pstart)) return tl::unexpected(make_error_code(errc::io_error));
      if(p >= part_hashes.size()) return tl::unexpected(make_error_code(errc::block_corrupt));  // 对端 hashset 不足
      crypto::MD4 m; m.update(buf);
      if(PartHash::from_bytes(m.finish()) != part_hashes[p])
        return tl::unexpected(make_error_code(errc::block_corrupt));
      part_done[p] = true;
      save_met();   // M2: part 完成 → 持久化 .part.met (崩溃后此 part 无需重哈希)
    }
  }
  return {};
}
// P4c-3 M3: 异步写盘 (raccoon 路径用)。状态/I/O 分离 —
//   状态 (block_done/part_filled/part_done) 仅网络线程变更; f 写/readback + MD4 经 disk_ex 卸载。
// 两段 post: →disk 执行 I/O →net 改状态。part 满时第三段: →disk readback+MD4 →net 翻 part_done+save_met。
// 单 disk 线程串行 f → 无竞态; 多 worker 并发同 part 块时, readback 触发必在各块写盘完成后
// (part_filled==plen 要求各块已计数, 而计数在各自 post(disk) 完成后) → readback 见完整 part。
boost::asio::awaitable<tl::expected<void,std::error_code>>
PartFile::Impl::write_block_async(std::uint64_t start, std::uint64_t end, std::span<const std::byte> data,
                            boost::asio::any_io_executor disk_ex){
  auto net_ex = co_await boost::asio::this_coro::executor;   // 网络线程 ex (post 前捕获)
  std::size_t part = static_cast<std::size_t>(start / PART_SIZE);
  std::size_t bip  = static_cast<std::size_t>((start % PART_SIZE) / AICH_BLOCK_SIZE);
  if(part >= block_done.size() || bip >= block_done[part].size())
    co_return tl::expected<void,std::error_code>{};
  if(block_done[part][bip]) co_return tl::expected<void,std::error_code>{};   // 幂等

  // 1) 磁盘写卸载到 disk_ex (disk 线程)。bind_executor 强制 resume 于 disk_ex
  //    (默认 post(ex, use_awaitable) resume 于协程关联 ex=net, 不卸载)。
  co_await boost::asio::post(disk_ex, boost::asio::bind_executor(disk_ex, boost::asio::use_awaitable));
  f.seekp(start);
  f.write(reinterpret_cast<const char*>(data.data()), data.size());
  // 2) 跳回网络线程变更状态
  co_await boost::asio::post(net_ex, boost::asio::bind_executor(net_ex, boost::asio::use_awaitable));
  block_done[part][bip] = true;
  std::uint64_t cur = start, finish = end;
  std::optional<std::size_t> filled_part;
  while(cur < finish){
    std::size_t p = static_cast<std::size_t>(cur / PART_SIZE);
    if(p >= part_done.size()) break;
    std::uint64_t pstart = static_cast<std::uint64_t>(p) * PART_SIZE;
    std::uint64_t pend = std::min((static_cast<std::uint64_t>(p)+1)*PART_SIZE, size);
    std::uint64_t seg_end = std::min(finish, pend);
    if(!part_done[p]) part_filled[p] += (seg_end - cur);
    cur = seg_end;
    if(!part_done[p] && part_filled[p] == (pend - pstart)) filled_part = p;
  }
  // 3) 若 part 满 → disk 线程 readback + MD4
  if(filled_part){
    std::size_t p = *filled_part;
    std::uint64_t pstart = static_cast<std::uint64_t>(p) * PART_SIZE;
    std::uint64_t pend = std::min((static_cast<std::uint64_t>(p)+1)*PART_SIZE, size);
    co_await boost::asio::post(disk_ex, boost::asio::bind_executor(disk_ex, boost::asio::use_awaitable));   // disk 线程
    std::vector<std::byte> buf(pend - pstart);
    f.flush();
    f.seekg(pstart);
    f.read(reinterpret_cast<char*>(buf.data()), pend - pstart);
    f.clear();
    bool iofail = (static_cast<std::uint64_t>(f.gcount()) != (pend - pstart));
    bool corrupt = false;
    if(!iofail){ if(p >= part_hashes.size()) corrupt = true;          // 对端 hashset 不足
                 else { crypto::MD4 m; m.update(buf);
                        if(PartHash::from_bytes(m.finish()) != part_hashes[p]) corrupt = true; } }
    co_await boost::asio::post(net_ex, boost::asio::bind_executor(net_ex, boost::asio::use_awaitable));    // 回网络线程
    if(iofail) co_return tl::unexpected(make_error_code(errc::io_error));
    if(corrupt) co_return tl::unexpected(make_error_code(errc::block_corrupt));
    part_done[p] = true;
    save_met();   // M2: 网络线程同步写 met (小文件)
  }
  co_return tl::expected<void,std::error_code>{};
}
bool PartFile::Impl::is_block_done(std::size_t part, std::size_t block_in_part) const noexcept {
  if(part >= block_done.size() || block_in_part >= block_done[part].size()) return false;
  return block_done[part][block_in_part];
}
std::vector<std::pair<std::size_t,std::size_t>> PartFile::Impl::pending_blocks() const {
  std::vector<std::pair<std::size_t,std::size_t>> out;
  for(std::size_t p=0; p<block_done.size(); ++p)
    for(std::size_t b=0; b<block_done[p].size(); ++b)
      if(!block_done[p][b]) out.emplace_back(p, b);
  return out;
}
bool PartFile::Impl::complete() const noexcept {
  for(bool d : part_done) if(!d) return false;
  return true;
}
std::vector<std::pair<std::uint64_t,std::uint64_t>> PartFile::Impl::gaps() const {
  std::vector<std::pair<std::uint64_t,std::uint64_t>> out;
  for(std::size_t i=0;i<part_done.size();++i){
    if(!part_done[i]){
      std::uint64_t pstart = i*PART_SIZE;
      std::uint64_t pend = std::min((i+1)*PART_SIZE, size);
      out.emplace_back(pstart, pend);
    }
  }
  return out;
}
tl::expected<ed2k::share::KnownFile,std::error_code> PartFile::Impl::to_known_file() const {
  if(!complete()) return tl::unexpected(make_error_code(errc::hash_mismatch));
  auto aich = aich_hash_file(path);
  if(!aich) return tl::unexpected(aich.error());
  ed2k::share::KnownFile f;
  f.hash = file_hash;
  f.aich_root = *aich;
  f.part_hashes = part_hashes;
  f.path = path;
  f.name = path.filename().string();
  f.size = size;
  return f;
}

PartFile::PartFile(const std::filesystem::path& path, std::uint64_t size, const FileHash& file_hash,
                   std::vector<PartHash> part_hashes)
  : impl_(std::make_unique<Impl>(path, size, file_hash, std::move(part_hashes))) {}
PartFile::~PartFile() = default;
PartFile::PartFile(PartFile&&) noexcept = default;
PartFile& PartFile::operator=(PartFile&&) noexcept = default;

bool PartFile::open_for_write() const noexcept { return impl_->open_for_write(); }
std::vector<std::uint32_t> PartFile::missing_parts_peer_has(const std::vector<bool>& peer_parts) const {
  return impl_->missing_parts_peer_has(peer_parts);
}
tl::expected<void,std::error_code> PartFile::write_block(std::uint64_t start, std::uint64_t end,
                                                         std::span<const std::byte> data) {
  return impl_->write_block(start, end, data);
}
boost::asio::awaitable<tl::expected<void,std::error_code>>
PartFile::write_block_async(std::uint64_t start, std::uint64_t end, std::span<const std::byte> data,
                            boost::asio::any_io_executor disk_ex) {
  co_return co_await impl_->write_block_async(start, end, data, std::move(disk_ex));
}
bool PartFile::is_block_done(std::size_t part, std::size_t block_in_part) const noexcept {
  return impl_->is_block_done(part, block_in_part);
}
std::vector<std::pair<std::size_t,std::size_t>> PartFile::pending_blocks() const {
  return impl_->pending_blocks();
}
bool PartFile::complete() const noexcept { return impl_->complete(); }
std::vector<std::pair<std::uint64_t,std::uint64_t>> PartFile::gaps() const { return impl_->gaps(); }
tl::expected<ed2k::share::KnownFile,std::error_code> PartFile::to_known_file() const {
  return impl_->to_known_file();
}
}
