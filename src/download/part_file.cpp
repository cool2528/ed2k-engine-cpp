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
#include <boost/asio/strand.hpp>
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
  // audit C9: 本 PartFile 专属的 disk strand —— f 是多源并发写同一 PartFile 时共享的磁盘资源
  // (见 write_block_async 顶部注释: 多 worker 可并发对同一 PartFile 发起磁盘跳转)。经此 strand
  // 序列化全部 disk 线程侧的 f 访问(seekp/write/seekg/read/flush), 使正确性不再仅依赖"disk 线程池
  // 恒为单线程"这一契约(IoRuntime::disk_pool_thread_count, 见 DiskPoolIsSingleThreadByContract) ——
  // 纵使该池未来被配置为多线程, 落在同一 strand 上的 handler 仍严格互斥执行, 不会出现 seekp/write
  // 交叉导致的错位写入(defense in depth, 不依赖易被无意改动的常量)。write_block_async 首次调用时
  // 按传入的 disk_ex 懒初始化(该协程同步起始段发生在网络线程, 与 SharedState "仅网络线程访问"的
  // 约束一致, 无需额外加锁); 此后同一 PartFile 生命周期内的所有磁盘跳转均复用该 strand。
  // 同步路径 write_block() 不经 disk_ex 卸载(调用方线程本身就是唯一访问者), 不涉及本 strand。
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> disk_strand;
  // E1: 块级落盘节流计数器 —— 每 kSaveMetBlockInterval 个新完成块调用一次 save_met(), 使 part
  // 尚未整体完成前也能定期把已下载块级进度落盘(而非只在 part 完成/显式 flush 时才落盘), 降低
  // 崩溃/异常退出时的重下代价。16 块 ≈ 16×AICH_BLOCK_SIZE ≈ 2.81MiB, 在"落盘 I/O 次数"与
  // "崩溃丢失窗口大小"间取的折中值(每 part 53 块的场景下, 一个 part 完成前大约再多出 3 次
  // 这样的中途落盘)。
  static constexpr std::size_t kSaveMetBlockInterval = 16;
  std::size_t blocks_since_save = 0;

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
      continue;
    }
    // E1: part 未整体完成(gap 覆盖或数据被截断)→ 尝试恢复块级进度, 使 resume 不必整 part 重下。
    // 与上面整 part 分支同一截断防御阈值(data_sz>=pend): 文件曾被截短到此 part 终点之前时,
    // 已落盘的块内容无法保证仍在盘上, 保守放弃恢复(回退到当前行为: 全 pending, 触发整 part 重下)。
    // 恢复的块仅标记 done, 不置 part_done(该 part 是否真正完整仍由 part 满时的 MD4 校验决定,
    // 与"同一次运行内下载中途"的块级 done 语义完全一致, 见 write_block 顶部块状态信任模型注释)。
    if(data_sz >= pend){
      auto it = std::find_if(r->partial_blocks.begin(), r->partial_blocks.end(),
                             [i](const auto& e){ return e.first == static_cast<std::uint32_t>(i); });
      if(it != r->partial_blocks.end() && it->second.size() == blocks_in_part(i)){
        std::uint64_t filled = 0;
        for(std::size_t b=0; b<it->second.size(); ++b){
          if(!it->second[b]) continue;
          block_done[i][b] = true;
          std::uint64_t bstart = pstart + static_cast<std::uint64_t>(b) * AICH_BLOCK_SIZE;
          std::uint64_t bend = std::min(bstart + AICH_BLOCK_SIZE, pend);
          filled += (bend - bstart);
        }
        part_filled[i] = filled;
      }
    }   // else: 保持 init 的 false (partial/截断 part 且无可信块级信息 → 整 part 重下)
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
// 落盘 .part.met: gaps() 为缺失整 part 区间 (part 粒度); partial_blocks 补充"未完成但已有块
// 进度"的 part 的块级位图(E1), 使 resume 能跳过已下载块而非整 part 重下。
void PartFile::Impl::save_met() const {
  ed2k::PartFileState st;
  st.hash = file_hash;
  st.part_hashes = part_hashes;
  st.size = size;
  st.gaps = gaps();
  // E1: 仅未完成且至少有一块已下载的 part 才落盘块位图(全 pending 的 part 落盘等同旧行为的
  // "不写", 保持 met 文件大小/字节内容与改动前一致 —— 常见的"整文件刚开始下载"场景不受影响)。
  for(std::size_t p=0; p<part_done.size(); ++p){
    if(part_done[p]) continue;
    bool any_done = false;
    for(bool d : block_done[p]) if(d){ any_done = true; break; }
    if(!any_done) continue;
    std::vector<std::uint8_t> bits(block_done[p].size());
    for(std::size_t b=0;b<block_done[p].size();++b) bits[b] = block_done[p][b] ? 1 : 0;
    st.partial_blocks.emplace_back(static_cast<std::uint32_t>(p), std::move(bits));
  }
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
  // E1: 块级落盘节流 —— 每 kSaveMetBlockInterval 个新完成块落盘一次, 覆盖 part 尚未整体完成
  // 前的中途进度(避免只靠 part 完成/显式 flush 才落盘, 崩溃窗口过大)。
  if(++blocks_since_save >= kSaveMetBlockInterval){ save_met(); blocks_since_save = 0; }
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
      if(PartHash::from_bytes(m.finish()) != part_hashes[p]){
        // audit C1: MD4 不符 = 已写入的字节损坏。重置该 part 的记账状态 (block_done 全 false +
        // part_filled 归零; part_done 此分支必为 false, 显式置位保持防御性), 使其全部块可重新下载
        // 并再次校验; 否则 :164 的幂等短路会让重下同一批块被静默丢弃 —— 损坏字节永久留盘, 该 part
        // 永不可验。仅重置内存记账, 不动盘上字节 (重下的块写入时会自然覆盖损坏数据)。
        block_done[p].assign(blocks_in_part(p), false);
        part_filled[p] = 0;
        part_done[p] = false;
        // E1: 立即落盘该重置, 避免此前(周期性落盘)残留的、把该 part 部分块标记为 done 的旧
        // .part.met 继续存在 —— 否则崩溃后 resume 会信任那些"实际已知损坏"的块级记录。
        save_met();
        blocks_since_save = 0;
        return tl::unexpected(make_error_code(errc::block_corrupt));
      }
      part_done[p] = true;
      save_met();   // M2: part 完成 → 持久化 .part.met (崩溃后此 part 无需重哈希)
      blocks_since_save = 0;
    }
  }
  return {};
}
// P4c-3 M3: 异步写盘 (raccoon 路径用)。状态/I/O 分离 —
//   状态 (block_done/part_filled/part_done) 仅网络线程变更; f 写/readback + MD4 经 disk_ex 卸载。
// 两段 post: →disk 执行 I/O →net 改状态。part 满时第三段: →disk readback+MD4 →net 翻 part_done+save_met。
// audit C9: 三处磁盘跳转均经本 PartFile 专属的 disk_strand 互斥(见 disk_strand 成员声明处注释)串行
// f 访问, 不依赖 disk 线程池是否单线程; 多 worker 并发同 part 块时, readback 触发必在各块写盘完成后
// (part_filled==plen 要求各块已计数, 而计数在各自磁盘跳转完成后) → readback 见完整 part。
boost::asio::awaitable<tl::expected<void,std::error_code>>
PartFile::Impl::write_block_async(std::uint64_t start, std::uint64_t end, std::span<const std::byte> data,
                            boost::asio::any_io_executor disk_ex){
  auto net_ex = co_await boost::asio::this_coro::executor;   // 网络线程 ex (post 前捕获)
  std::size_t part = static_cast<std::size_t>(start / PART_SIZE);
  std::size_t bip  = static_cast<std::size_t>((start % PART_SIZE) / AICH_BLOCK_SIZE);
  if(part >= block_done.size() || bip >= block_done[part].size())
    co_return tl::expected<void,std::error_code>{};
  if(block_done[part][bip]) co_return tl::expected<void,std::error_code>{};   // 幂等

  // audit C9: 懒初始化本 PartFile 的 disk strand(仅首次调用按传入 disk_ex 构造, 之后复用同一个),
  // 下面两处磁盘跳转均经该 strand 而非裸 disk_ex —— 详见 disk_strand 成员声明处注释。
  if(!disk_strand) disk_strand.emplace(disk_ex);
  auto& disk_strand_ex = *disk_strand;

  // 1) 磁盘写卸载到 disk_strand_ex (disk 线程, 经 strand 互斥)。bind_executor 强制 resume 于
  //    disk_strand_ex (默认 post(ex, use_awaitable) resume 于协程关联 ex=net, 不卸载)。
  co_await boost::asio::post(disk_strand_ex, boost::asio::bind_executor(disk_strand_ex, boost::asio::use_awaitable));
  f.seekp(start);
  f.write(reinterpret_cast<const char*>(data.data()), data.size());
  // 2) 跳回网络线程变更状态
  co_await boost::asio::post(net_ex, boost::asio::bind_executor(net_ex, boost::asio::use_awaitable));
  block_done[part][bip] = true;
  // E1: 块级落盘节流(镜像 sync write_block); 已在网络线程(状态变更仅网络线程), 直接同步落盘。
  if(++blocks_since_save >= kSaveMetBlockInterval){ save_met(); blocks_since_save = 0; }
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
    co_await boost::asio::post(disk_strand_ex, boost::asio::bind_executor(disk_strand_ex, boost::asio::use_awaitable));   // disk 线程 (经 strand 互斥)
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
    if(corrupt){
      // audit C1 (镜像 sync write_block): MD4 不符 = 已写字节损坏。此刻已回到网络线程(状态仅网络线程
      // 变更, 见本函数顶部注释), 重置该 part 记账(block_done 全 false + part_filled 归零 + part_done
      // 置 false), 使全部块可重下重验; 否则 :218 的幂等短路会让重下同批块被静默丢弃 —— 损坏字节永久
      // 留盘、该 part 永不可验。仅重置内存记账, 不动盘上字节(重下块写入自然覆盖)。write_block_async 是
      // MultiSourceDownload 生产主路径实际调用的写入, 必须与 sync write_block 同样重置才算 C1 完整。
      block_done[p].assign(blocks_in_part(p), false);
      part_filled[p] = 0;
      part_done[p] = false;
      // E1: 立即落盘该重置(镜像 sync write_block), 避免残留的旧 .part.met 继续信任这些已知损坏的块。
      save_met();
      blocks_since_save = 0;
      co_return tl::unexpected(make_error_code(errc::block_corrupt));
    }
    part_done[p] = true;
    save_met();   // M2: 网络线程同步写 met (小文件)
    blocks_since_save = 0;
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
void PartFile::save_met() const { impl_->save_met(); }
tl::expected<ed2k::share::KnownFile,std::error_code> PartFile::to_known_file() const {
  return impl_->to_known_file();
}
}
