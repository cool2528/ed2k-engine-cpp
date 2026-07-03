#include "ed2k/download/part_file.hpp"
#include "ed2k/metfile/known_part_met.hpp"
#include "crypto/md4.hpp"
#include <optional>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/this_coro.hpp>
namespace ed2k::download {
PartFile::PartFile(const std::filesystem::path& path, std::uint64_t size, const FileHash& file_hash, std::vector<PartHash> part_hashes)
  : path_(path), met_path_(path), size_(size), file_hash_(file_hash), part_hashes_(std::move(part_hashes)) {
  met_path_ += ".part.met";
  if(part_hashes_.empty()) part_hashes_.push_back(file_hash_);
  part_done_.assign(part_hashes_.size(), false);
  part_filled_.assign(part_hashes_.size(), 0);
  // per-part 块位图: 每 part ceil(part_size/AICH_BLOCK_SIZE) 块, 块不跨 part 边界。
  block_done_.resize(part_hashes_.size());
  for(std::size_t p=0;p<part_hashes_.size();++p)
    block_done_[p].assign(blocks_in_part(p), false);
  if(!std::filesystem::exists(path_)) { std::ofstream c(path_, std::ios::binary); }
  f_.open(path_, std::ios::binary | std::ios::in | std::ios::out);
  // P4c-3 M2: met-first 续传。.part.met 有效 → 恢复 part_done_ 无需重哈希 (D1 性能);
  //          缺失/损坏/陈旧 (hash 不匹配) → 回退 rehash_all (P4a 安全网)。
  if(!try_load_met()) rehash_all();
}
// .part.met 解析恢复。仅当 magic 有效且 hash/part_hashes 与本文件一致时应用 (否则视为陈旧)。
// 信任模型: met 标 done 的 part 直接受信 (写盘时已 MD4 校验); 仅以 file_size(data) >= part_end
// 防截断, 不再回读重哈希。partial part (met 中为 gap) → 重下整 part (块级不持久化, 与 P4a 一致)。
bool PartFile::try_load_met(){
  if(!std::filesystem::exists(met_path_)) return false;
  std::ifstream m(met_path_, std::ios::binary);
  if(!m.is_open()) return false;
  std::vector<char> raw((std::istreambuf_iterator<char>(m)), std::istreambuf_iterator<char>());
  std::vector<std::byte> buf(raw.size());
  for(std::size_t i=0;i<raw.size();++i) buf[i] = std::byte(static_cast<unsigned char>(raw[i]));
  auto r = ed2k::parse_part_met(buf);
  if(!r) return false;
  if(!(r->hash == file_hash_) || r->part_hashes != part_hashes_) return false;   // 陈旧 met (异文件)
  std::uint64_t data_sz = std::filesystem::exists(path_) ? std::filesystem::file_size(path_) : 0;
  for(std::size_t i=0;i<part_hashes_.size();++i){
    std::uint64_t pstart = static_cast<std::uint64_t>(i)*PART_SIZE;
    std::uint64_t pend = std::min(static_cast<std::uint64_t>(pstart+PART_SIZE), size_);
    bool gap_overlaps = false;
    for(auto& g : r->gaps){
      if(g.first < pend && g.second > pstart){ gap_overlaps = true; break; }
    }
    if(!gap_overlaps && data_sz >= pend){
      part_done_[i] = true; part_filled_[i] = pend - pstart;
      block_done_[i].assign(blocks_in_part(i), true);
    }   // else: 保持 init 的 false (partial/截断 part → 重下)
  }
  return true;
}
// 回退路径 (P4a 原续传): 逐 part 回读 + MD4 校验。met 缺失/损坏/陈旧时使用。
void PartFile::rehash_all(){
  for(std::size_t i=0;i<part_hashes_.size();++i){
    std::uint64_t pstart = i*PART_SIZE;
    std::uint64_t pend = std::min((i+1)*PART_SIZE, size_);
    std::uint64_t plen = pend-pstart;
    if(plen==0) continue;
    std::vector<std::byte> buf(plen);
    f_.seekg(pstart);
    f_.read(reinterpret_cast<char*>(buf.data()), plen);
    if(static_cast<std::uint64_t>(f_.gcount()) == plen){
      crypto::MD4 m; m.update(buf);
      if(PartHash::from_bytes(m.finish()) == part_hashes_[i]){
        part_done_[i] = true; part_filled_[i] = plen;
      }
    }
    f_.clear();
  }
  // 推导 per-part block_done_: 一个 part 的 MD4 校验通过 → 该 part 所有块均 done。
  for(std::size_t p=0;p<part_hashes_.size();++p){
    if(part_done_[p]) block_done_[p].assign(blocks_in_part(p), true);
  }
}
// 落盘 .part.met: gaps() 为缺失整 part 区间 (与 part 粒度状态模型一致)。
void PartFile::save_met() const {
  ed2k::PartFileState st;
  st.hash = file_hash_;
  st.part_hashes = part_hashes_;
  st.gaps = gaps();
  auto bytes = ed2k::write_part_met(st);
  std::ofstream m(met_path_, std::ios::binary | std::ios::trunc);
  if(!m.is_open()) return;
  m.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}
bool PartFile::open_for_write() const noexcept { return f_.is_open(); }
std::vector<std::uint32_t> PartFile::missing_parts_peer_has(const std::vector<bool>& peer_parts) const {
  std::vector<std::uint32_t> out;
  for(std::size_t i=0;i<part_done_.size() && i<peer_parts.size();++i)
    if(!part_done_[i] && peer_parts[i]) out.push_back(static_cast<std::uint32_t>(i));
  return out;
}
// 写入一个 per-part 块 [start, end)。块绝不跨 part 边界(per-part 模型):
//   part = start/PART_SIZE, block_in_part = (start%PART_SIZE)/AICH_BLOCK_SIZE。
// 一次连续写盘, 然后按 part 边界累计 part_filled_ (per-part 块恒落单 part, 循环退化为单段),
// 该 part 字节满即回读整 part 做 MD4 校验。part 完成时落盘 .part.met (M2 续传持久化)。
tl::expected<void,std::error_code> PartFile::write_block(std::uint64_t start, std::uint64_t end, std::span<const std::byte> data){
  std::size_t part = static_cast<std::size_t>(start / PART_SIZE);
  std::size_t bip  = static_cast<std::size_t>((start % PART_SIZE) / AICH_BLOCK_SIZE);
  if(part >= block_done_.size() || bip >= block_done_[part].size()) return {};
  if(block_done_[part][bip]) return {};   // 幂等: 已置位直接成功, 不重复写盘/校验/计数
  f_.seekp(start);
  f_.write(reinterpret_cast<const char*>(data.data()), data.size());
  block_done_[part][bip] = true;
  // 按 part 边界切分 [start, end) 累计 part_filled_ 并触发 MD4 (per-part 块恒单 part)。
  std::uint64_t cur = start;
  std::uint64_t finish = end;
  while(cur < finish){
    std::size_t p = static_cast<std::size_t>(cur / PART_SIZE);
    if(p >= part_done_.size()) break;
    std::uint64_t pstart = static_cast<std::uint64_t>(p) * PART_SIZE;
    std::uint64_t pend = std::min((static_cast<std::uint64_t>(p)+1)*PART_SIZE, size_);
    std::uint64_t seg_end = std::min(finish, pend);
    if(!part_done_[p]) part_filled_[p] += (seg_end - cur);
    cur = seg_end;
    // 该 part 字节满: 回读整 part 做 MD4 校验
    if(!part_done_[p] && part_filled_[p] == (pend - pstart)){
      std::vector<std::byte> buf(pend - pstart);
      f_.flush();
      f_.seekg(pstart);
      f_.read(reinterpret_cast<char*>(buf.data()), pend - pstart);
      f_.clear();
      if(static_cast<std::uint64_t>(f_.gcount()) != (pend - pstart)) return tl::unexpected(make_error_code(errc::io_error));
      crypto::MD4 m; m.update(buf);
      if(PartHash::from_bytes(m.finish()) != part_hashes_[p])
        return tl::unexpected(make_error_code(errc::block_corrupt));
      part_done_[p] = true;
      save_met();   // M2: part 完成 → 持久化 .part.met (崩溃后此 part 无需重哈希)
    }
  }
  return {};
}
// P4c-3 M3: 异步写盘 (raccoon 路径用)。状态/I/O 分离 —
//   状态 (block_done_/part_filled_/part_done_) 仅网络线程变更; f_ 写/readback + MD4 经 disk_ex 卸载。
// 两段 post: →disk 执行 I/O →net 改状态。part 满时第三段: →disk readback+MD4 →net 翻 part_done_+save_met。
// 单 disk 线程串行 f_ → 无竞态; 多 worker 并发同 part 块时, readback 触发必在各块写盘完成后
// (part_filled_==plen 要求各块已计数, 而计数在各自 post(disk) 完成后) → readback 见完整 part。
boost::asio::awaitable<tl::expected<void,std::error_code>>
PartFile::write_block_async(std::uint64_t start, std::uint64_t end, std::span<const std::byte> data,
                            boost::asio::any_io_executor disk_ex){
  auto net_ex = co_await boost::asio::this_coro::executor;   // 网络线程 ex (post 前捕获)
  std::size_t part = static_cast<std::size_t>(start / PART_SIZE);
  std::size_t bip  = static_cast<std::size_t>((start % PART_SIZE) / AICH_BLOCK_SIZE);
  if(part >= block_done_.size() || bip >= block_done_[part].size())
    co_return tl::expected<void,std::error_code>{};
  if(block_done_[part][bip]) co_return tl::expected<void,std::error_code>{};   // 幂等

  // 1) 磁盘写卸载到 disk_ex (disk 线程)。bind_executor 强制 resume 于 disk_ex
  //    (默认 post(ex, use_awaitable) resume 于协程关联 ex=net, 不卸载)。
  co_await boost::asio::post(disk_ex, boost::asio::bind_executor(disk_ex, boost::asio::use_awaitable));
  f_.seekp(start);
  f_.write(reinterpret_cast<const char*>(data.data()), data.size());
  // 2) 跳回网络线程变更状态
  co_await boost::asio::post(net_ex, boost::asio::bind_executor(net_ex, boost::asio::use_awaitable));
  block_done_[part][bip] = true;
  std::uint64_t cur = start, finish = end;
  std::optional<std::size_t> filled_part;
  while(cur < finish){
    std::size_t p = static_cast<std::size_t>(cur / PART_SIZE);
    if(p >= part_done_.size()) break;
    std::uint64_t pstart = static_cast<std::uint64_t>(p) * PART_SIZE;
    std::uint64_t pend = std::min((static_cast<std::uint64_t>(p)+1)*PART_SIZE, size_);
    std::uint64_t seg_end = std::min(finish, pend);
    if(!part_done_[p]) part_filled_[p] += (seg_end - cur);
    cur = seg_end;
    if(!part_done_[p] && part_filled_[p] == (pend - pstart)) filled_part = p;
  }
  // 3) 若 part 满 → disk 线程 readback + MD4
  if(filled_part){
    std::size_t p = *filled_part;
    std::uint64_t pstart = static_cast<std::uint64_t>(p) * PART_SIZE;
    std::uint64_t pend = std::min((static_cast<std::uint64_t>(p)+1)*PART_SIZE, size_);
    co_await boost::asio::post(disk_ex, boost::asio::bind_executor(disk_ex, boost::asio::use_awaitable));   // disk 线程
    std::vector<std::byte> buf(pend - pstart);
    f_.flush();
    f_.seekg(pstart);
    f_.read(reinterpret_cast<char*>(buf.data()), pend - pstart);
    f_.clear();
    bool iofail = (static_cast<std::uint64_t>(f_.gcount()) != (pend - pstart));
    bool corrupt = false;
    if(!iofail){ crypto::MD4 m; m.update(buf);
                 if(PartHash::from_bytes(m.finish()) != part_hashes_[p]) corrupt = true; }
    co_await boost::asio::post(net_ex, boost::asio::bind_executor(net_ex, boost::asio::use_awaitable));    // 回网络线程
    if(iofail) co_return tl::unexpected(make_error_code(errc::io_error));
    if(corrupt) co_return tl::unexpected(make_error_code(errc::block_corrupt));
    part_done_[p] = true;
    save_met();   // M2: 网络线程同步写 met (小文件)
  }
  co_return tl::expected<void,std::error_code>{};
}
bool PartFile::is_block_done(std::size_t part, std::size_t block_in_part) const noexcept {
  if(part >= block_done_.size() || block_in_part >= block_done_[part].size()) return false;
  return block_done_[part][block_in_part];
}
std::vector<std::pair<std::size_t,std::size_t>> PartFile::pending_blocks() const {
  std::vector<std::pair<std::size_t,std::size_t>> out;
  for(std::size_t p=0; p<block_done_.size(); ++p)
    for(std::size_t b=0; b<block_done_[p].size(); ++b)
      if(!block_done_[p][b]) out.emplace_back(p, b);
  return out;
}
bool PartFile::complete() const noexcept {
  for(bool d : part_done_) if(!d) return false;
  return true;
}
std::vector<std::pair<std::uint64_t,std::uint64_t>> PartFile::gaps() const {
  std::vector<std::pair<std::uint64_t,std::uint64_t>> out;
  for(std::size_t i=0;i<part_done_.size();++i){
    if(!part_done_[i]){
      std::uint64_t pstart = i*PART_SIZE;
      std::uint64_t pend = std::min((i+1)*PART_SIZE, size_);
      out.emplace_back(pstart, pend);
    }
  }
  return out;
}
}
