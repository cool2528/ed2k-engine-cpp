#include "ed2k/session/session.hpp"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <exception>
#include <fstream>
#include <map>
#include <unordered_set>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <spdlog/spdlog.h>
#include "ed2k/download/download.hpp"
#include "ed2k/infra/http_download.hpp"
#include "ed2k/kad/network.hpp"
#include "ed2k/kad/nodes_dat.hpp"
#include "ed2k/metfile/server_met.hpp"
#include "ed2k/peer/inbound_listener.hpp"
#include "ed2k/server/connection.hpp"
#include "ed2k/util/error.hpp"

namespace ed2k::session {
namespace asio = boost::asio;

namespace {
// 读整个文件到内存; 不存在/失败返回空(login_with_rotation 空 met 时走内建 fallback 服务器)
std::vector<std::byte> read_file_bytes(const std::filesystem::path& p){
  std::ifstream f(p, std::ios::binary);
  if(!f) return {};
  std::vector<char> buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  std::vector<std::byte> out(buf.size());
  std::memcpy(out.data(), buf.data(), buf.size());
  return out;
}
// persist_server_met 临时文件名的进程内自增序号(M1: 避免同目录多 Session 实例并发落盘时
// 固定文件名互相覆盖; 结合 tcp_port 进一步降低跨进程碰撞概率)。
std::atomic<std::uint64_t> g_persist_seq{0};
}

struct TaskEntry {
  std::uint64_t id = 0;
  Ed2kFileLink link;
  std::filesystem::path out_path;
  TaskState state = TaskState::queued;
  std::error_code error;
  std::uint64_t bytes_done = 0;
  std::uint64_t speed_bps = 0;
  std::uint64_t last_sample_bytes = 0;
  std::chrono::steady_clock::time_point last_sample_time{};
  std::size_t known_sources = 0;
  std::shared_ptr<bool> stop;        // 本代运行的停止标志
  std::uint32_t generation = 0;      // resume 递增; 旧代协程回写作废
};

struct Session::Impl : std::enable_shared_from_this<Session::Impl> {
  net::IoRuntime& rt;
  SessionConfig cfg;
  std::uint64_t next_id = 1;
  std::map<std::uint64_t, TaskEntry> tasks;
  std::size_t active = 0;
  bool shutting_down = false;
  std::function<void(const SessionEvent&)> handler;
  std::vector<std::byte> server_met_bytes;
  // 服务器列表(server.met 解析结果); add_server/remove_server/update_server_met 修改后立即落盘。
  ServerList servers;
  // 当前登录会话; nullopt 表示未连接。
  std::optional<app::LoginSession> login;
  server::ServerConnection::Subscription server_sub;
  ServerStateEvent server_state;
  // 每次 connect_server/disconnect_server 递增, 令在途的旧 connect_server 初始快照读窗口
  // 协程在挂起恢复后发现代次不匹配而安静退出, 不误用已失效/已被替换的 login/conn
  // (方案 C: 见下方 connect_server 注释, 不再有常驻 receive_loop, 但快照窗口本身跨越
  // 多次 co_await, 仍需此重入防护)。
  std::uint32_t server_generation = 0;
  // connect_server 初始快照窗口内, on_event 回调收到 ServerIdentEvent 时置位, 供窗口循环
  // 判断是否可提前结束(拿到服务器自报的真实身份即可, 无需耗满整个窗口预算)。
  bool snapshot_ident_seen = false;
  // cancel(remove_files=true) 在任务运行中被调用时, 文件此刻仍被 PartFile 打开(Windows 删除会失败);
  // 删除动作先记录到此处, 待协程退出(句柄已释放)后由 on_task_coroutine_exit 执行。键 = 任务 id。
  std::map<std::uint64_t, std::vector<std::filesystem::path>> pending_remove;
  // 按任务 id 统计在途 run_task 协程数, 跨代累计(不放 TaskEntry: cancel() erase 任务后仍需保留计数)。
  // pause→resume 竞态下同一 id 可能有新旧两代协程并存(旧代挂起未醒, 新代已 pump 启动),
  // 用布尔标记无法表达"多个在途"这一状态, 必须用计数; 只有归零(最后一个持句柄的协程退出)才安全删文件。
  std::map<std::uint64_t, int> inflight;
  // Kad(DHT) 网络实例; cfg.enable_kad=false 时恒为空。run_task 构建 Builder 时若非空则追加
  // .kad_network(*kad), 交由 MultiSourceDownload 在缺源时自动增源。
  std::unique_ptr<kad::KadNetwork> kad;

  Impl(net::IoRuntime& rt_arg, SessionConfig cfg_arg)
    : rt(rt_arg), cfg(std::move(cfg_arg)) {
    server_met_bytes = read_file_bytes(cfg.data_dir / "server.met");
    // 解析失败(文件不存在/损坏)保持 servers 为空表; login_with_rotation 内部走内建 fallback。
    if(auto parsed = parse_server_met(server_met_bytes)) servers = std::move(*parsed);
    if(cfg.enable_kad){
      const auto user_hash = effective_user_hash();
      kad::KadNetworkOptions opts;
      opts.id = kad::KadID::from_user_hash(user_hash, 1);
      opts.ip = IPv4::from_dotted("0.0.0.0").value();   // 本地公网 IP 未知, 占位(与 CLI 一致)
      opts.udp_port = cfg.kad_udp_port;
      opts.tcp_port = cfg.tcp_port;
      opts.version = kad::kad2_version;
      opts.user_hash = kad::KadID::from_bytes(user_hash.bytes());
      kad = std::make_unique<kad::KadNetwork>(rt.executor(), opts);
    }
  }

  // cfg.user_hash 未设置时的默认值(与既有 login_params() 保持一致的占位 user_hash)。
  UserHash effective_user_hash() const {
    return cfg.user_hash.value_or(*UserHash::from_hex("0123456789abcdeffedcba9876543210"));
  }

  // 把 servers 落盘到 cfg.data_dir/server.met: 写临时文件后 rename 原子替换。
  // 无论落盘是否成功, server_met_bytes 都同步更新, 保证运行期(login_with_rotation 的轮换目标)
  // 立即反映最新列表, 不依赖磁盘 IO 结果。
  void persist_server_met(){
    auto bytes = write_server_met(servers);
    server_met_bytes = bytes;
    std::error_code ec;
    std::filesystem::create_directories(cfg.data_dir, ec);
    // M1: 临时文件名带 tcp_port + 进程内自增序号, 避免同目录多 Session 实例(或同实例并发调用)
    // 固定文件名 "server.met.tmp" 互相覆盖导致的写坏/丢数据。
    const auto seq = g_persist_seq.fetch_add(1, std::memory_order_relaxed);
    auto tmp_path = cfg.data_dir /
      ("server.met." + std::to_string(cfg.tcp_port) + "." + std::to_string(seq) + ".tmp");
    auto final_path = cfg.data_dir / "server.met";
    std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
    if(!f){
      // M2: 落盘失败不再静默; 内存态(server_met_bytes/servers)已更新, 仅本次持久化放弃。
      spdlog::warn("Session::persist_server_met: failed to open temp file {}", tmp_path.string());
      return;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    f.close();
    std::filesystem::rename(tmp_path, final_path, ec);   // 原子替换
    if(ec){
      spdlog::warn("Session::persist_server_met: rename {} -> {} failed: {}",
                   tmp_path.string(), final_path.string(), ec.message());
    }
  }

  // 把当前 Kad 路由表联系人落盘到 cfg.data_dir/nodes.dat: 写临时文件后 rename 原子替换,
  // 与 persist_server_met 同构(临时文件名带 tcp_port + 进程内自增序号防并发覆盖)。仅在
  // shutdown() 里调用一次(kad->close() 之后), 不在运行期频繁落盘。
  void persist_nodes_dat(){
    if(!kad) return;
    auto bytes = kad::write_nodes_dat(kad->routing_table().all_contacts());
    std::error_code ec;
    std::filesystem::create_directories(cfg.data_dir, ec);
    const auto seq = g_persist_seq.fetch_add(1, std::memory_order_relaxed);
    auto tmp_path = cfg.data_dir /
      ("nodes.dat." + std::to_string(cfg.tcp_port) + "." + std::to_string(seq) + ".tmp");
    auto final_path = cfg.data_dir / "nodes.dat";
    std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
    if(!f){
      spdlog::warn("Session::persist_nodes_dat: failed to open temp file {}", tmp_path.string());
      return;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    f.close();
    std::filesystem::rename(tmp_path, final_path, ec);
    if(ec){
      spdlog::warn("Session::persist_nodes_dat: rename {} -> {} failed: {}",
                   tmp_path.string(), final_path.string(), ec.message());
    }
  }

  // 断开当前服务器连接: 幂等(未连接时 no-op)。递增 server_generation 使在途的 connect_server
  // 快照窗口协程在挂起恢复后发现代次不匹配而安静退出, 不重复 emit、不误用已失效连接。
  void disconnect_server_internal(){
    if(!login) return;
    login->conn.close();
    login.reset();
    server_sub = server::ServerConnection::Subscription{};
    ++server_generation;
    server_state.connected = false;
    emit(server_state);
  }

  void emit(const SessionEvent& ev){ if(handler) handler(ev); }
  void set_state(TaskEntry& t, TaskState s, std::error_code ec = {}){
    t.state = s; t.error = ec;
    if(s == TaskState::failed) t.speed_bps = 0;   // 失败态清空速度, 避免残留旧速度
    emit(TaskStateEvent{t.id, s, ec});
  }
  // 指定代次仍存活的任务; 不匹配返回 nullptr(任务已删/已重启新代)
  TaskEntry* find_alive(std::uint64_t id, std::uint32_t gen){
    auto it = tasks.find(id);
    if(it == tasks.end() || it->second.generation != gen) return nullptr;
    return &it->second;
  }
  server::LoginParams login_params() const {
    server::LoginParams p;
    p.nickname = cfg.nickname;
    p.client_port = cfg.tcp_port;
    p.user_hash = effective_user_hash();
    return p;
  }
  // 启动排队任务直到并发上限
  void pump(){
    if(shutting_down) return;
    // max_concurrent_tasks == 0 会使下面的 active>=上限 恒真, 队列永不启动(死锁); clamp 到至少 1
    const std::size_t max_slots = std::max<std::size_t>(1, cfg.max_concurrent_tasks);
    for(auto& [id, t] : tasks){
      if(active >= max_slots) break;
      if(t.state != TaskState::queued) continue;
      ++active;
      t.stop = std::make_shared<bool>(false);
      ++inflight[id];                   // 本代协程即将启动, 计数 +1, 供 cancel() 判断是否需延迟删文件
      set_state(t, TaskState::connecting);
      asio::co_spawn(rt.context(), run_task(weak_from_this(), id, t.generation), asio::detached);
    }
  }
  void finish_slot(){
    if(active > 0) --active;
    pump();
  }
  // 协程退出统一收尾入口: run_task 所有出口都必须调用它(而非直接 finish_slot), 以避免遗漏
  // pending_remove 的清理。不依赖 TaskEntry 是否存活: cancel() 已把任务从 tasks erase,
  // 这里只按 id 匹配 pending_remove/inflight, 与 TaskEntry 生命周期解耦。
  void on_task_coroutine_exit(std::uint64_t id){
    if(auto it = inflight.find(id); it != inflight.end()){
      if(--it->second <= 0){
        inflight.erase(it);
        // 计数归零: 该 id 所有代的协程都已退出, PartFile 句柄全部释放, 此刻删文件在 Windows 上是安全的。
        // 若仍 >0(pause/resume 竞态导致新旧两代协程并存), 说明还有协程持有句柄, 本次不删, 等下一次归零。
        if(auto pr = pending_remove.find(id); pr != pending_remove.end()){
          for(const auto& p : pr->second){ std::error_code ec; std::filesystem::remove(p, ec); }
          pending_remove.erase(pr);
        }
      }
    }
    finish_slot();
  }

  // 任务编排协程(static + weak_ptr: Session 析构后挂起协程安全退化为 no-op)。
  // 流程复刻 app::download_link: login_with_rotation → get_sources → MultiSourceDownload。
  static asio::awaitable<void> run_task(std::weak_ptr<Impl> weak, std::uint64_t id, std::uint32_t gen){
    auto self = weak.lock();
    if(!self) co_return;
    auto ex = self->rt.executor();
    auto* t = self->find_alive(id, gen);
    if(!t || t->state != TaskState::connecting){ self->on_task_coroutine_exit(id); co_return; }
    auto stop = t->stop;
    auto link = t->link;
    auto out_path = t->out_path;

    auto lg = co_await app::login_with_rotation(ex, self->server_met_bytes, self->cfg.server_override,
                                                self->login_params(), self->cfg.per_server_timeout);
    self = weak.lock(); if(!self) co_return;
    t = self->find_alive(id, gen);
    if(!t){ self->on_task_coroutine_exit(id); co_return; }
    if(stop && *stop){ self->on_task_coroutine_exit(id); co_return; }        // pause/cancel 已改状态, 不覆盖
    if(!lg){ self->set_state(*t, TaskState::failed, lg.error()); self->on_task_coroutine_exit(id); co_return; }

    auto gs = co_await lg->conn.get_sources(link.hash, link.size, self->cfg.per_server_timeout);
    self = weak.lock(); if(!self) co_return;
    t = self->find_alive(id, gen);
    if(!t){ self->on_task_coroutine_exit(id); co_return; }
    if(stop && *stop){ self->on_task_coroutine_exit(id); co_return; }
    if(!gs){ self->set_state(*t, TaskState::failed, gs.error()); self->on_task_coroutine_exit(id); co_return; }
    t->known_sources = gs->sources.size();
    if(gs->sources.empty()){
      self->set_state(*t, TaskState::failed, make_error_code(errc::file_not_found));
      self->on_task_coroutine_exit(id); co_return;
    }

    // LowID 源回调需要 listener; bind 失败(端口占用)时保持为空, worker 守卫优雅跳过 LowID
    bool has_low_id = std::any_of(gs->sources.begin(), gs->sources.end(),
                                  [](const server::SourceEndpoint& s){ return s.low_id(); });
    std::optional<peer::InboundListener> listener;
    if(has_low_id){
      try { listener.emplace(ex, self->cfg.tcp_port); }
      catch(const std::exception&) { /* 端口被占 — LowID 源跳过 */ }
    }

    self->set_state(*t, TaskState::downloading);
    auto builder = download::MultiSourceDownload::Builder(ex)
      .out(out_path).hash(link.hash).size(link.size)
      .aich(std::nullopt)
      .sources(std::move(gs->sources))
      .obfuscation(self->cfg.obfuscation, self->cfg.user_hash)
      .server(lg->conn)
      .disk_executor(self->rt.disk_executor())
      .stop_flag(stop)
      .on_progress([weak, id, gen](std::uint64_t done, std::uint64_t){
        if(auto s = weak.lock())
          if(auto* e = s->find_alive(id, gen)) e->bytes_done = done;
      });
    if(listener) builder.listener(*listener);
    // enable_kad 时把 Kad 网络注入 Builder; MultiSourceDownload::run() 内部若发现 sources 不足
    // 会自动调用 kad_network.find_sources(...) 增源(既有逻辑, 见 download.cpp)。
    if(self->kad) builder.kad_network(*self->kad);
    auto dl = builder.build();
    auto r = co_await dl.run(self->cfg.task_io_timeout, 3);

    self = weak.lock(); if(!self) co_return;
    t = self->find_alive(id, gen);
    if(t){
      if(r){
        t->bytes_done = link.size;
        t->speed_bps = 0;
        self->set_state(*t, TaskState::completed);
      } else if(r.error() == make_error_code(errc::cancelled)) {
        // pause()/cancel() 已设终态并发过事件, 此处不覆盖
        t->speed_bps = 0;
      } else {
        self->set_state(*t, TaskState::failed, r.error());
      }
    }
    self->on_task_coroutine_exit(id);
    co_return;
  }

  // 1s 速度采样循环(差分)。weak_ptr 防悬垂; shutdown 后自然退出。
  static asio::awaitable<void> sampler(std::weak_ptr<Impl> weak){
    for(;;){
      auto self = weak.lock();
      if(!self || self->shutting_down) co_return;
      asio::steady_timer timer(self->rt.context());
      timer.expires_after(std::chrono::seconds(1));
      self.reset();                                    // 等待期间不持有 Impl
      co_await timer.async_wait(asio::use_awaitable);
      self = weak.lock();
      if(!self || self->shutting_down) co_return;
      const auto now = std::chrono::steady_clock::now();
      for(auto& [id, t] : self->tasks){
        if(t.state != TaskState::downloading) continue;
        if(t.last_sample_time.time_since_epoch().count() != 0){
          auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - t.last_sample_time).count();
          if(ms > 0 && t.bytes_done >= t.last_sample_bytes)
            t.speed_bps = (t.bytes_done - t.last_sample_bytes) * 1000 / static_cast<std::uint64_t>(ms);
        }
        t.last_sample_bytes = t.bytes_done;
        t.last_sample_time = now;
      }
    }
  }

  // Kad 常驻协程(static + weak_ptr: Session 析构后挂起协程安全退化为 no-op, 与 run_task/sampler
  // 同构)。先用 nodes.dat 解析出的 seeds 做一次性 bootstrap(填充路由表), 完成后转入 serve_once
  // 常驻循环(应答入站 Kad 请求, 使本节点成为正常网络参与者)。
  // 刻意合并成单协程顺序执行(而非 bootstrap/serve 各自独立 co_spawn): KadNetwork 的 UDP 收包
  // (recv_kad_packet)是无请求/响应 ID 分发的单读者模型——bootstrap()/serve_once() 都直接
  // co_await 同一个 socket 的 recv, 谁在当前时刻发起 recv 谁就拿走下一个到达的数据报。若两者
  // 并发跑在同一个 KadNetwork 实例上, 会互相偷走对方期待的响应包(与 Task 6/7 里
  // server::ServerConnection 必须"单读者"的既有约束同构)。顺序执行从根上避免这个自引入的竞态。
  // 已知风险(超出本任务范围, 见 task-8-brief.md "已识别的实现风险"): run_task 里
  // MultiSourceDownload::run() 内部调用的 kad_network.find_sources(...) 仍可能与这里的
  // serve_once 常驻循环在同一 KadNetwork 实例上并发发起 recv, 根治需要在 KadNetwork 内部引入
  // 按 opcode/target 的请求路由, 属于更底层改动。
  static asio::awaitable<void> kad_run(std::weak_ptr<Impl> weak, std::vector<kad::Contact> seeds){
    auto self = weak.lock();
    if(!self || self->shutting_down || !self->kad) co_return;
    auto bootstrapped = co_await self->kad->bootstrap(seeds, std::chrono::milliseconds(1500));
    (void)bootstrapped;   // 失败(无种子/全部超时)不致命; serve_once 循环仍可被动学习到联系人
    self = weak.lock();
    if(!self || self->shutting_down || !self->kad) co_return;

    for(;;){
      // self 在 co_await 期间保持存活(持有额外 shared_ptr 引用), 保证 self->kad 指向的
      // KadNetwork 不会被析构; shutdown() 会调用 kad->close() 促使 recv 尽快因 socket 关闭
      // 而返回错误, 不会无限期挂起到 Impl 引用计数归零才被回收。
      auto served = co_await self->kad->serve_once(std::chrono::milliseconds(2000));
      (void)served;       // 超时/解析失败/socket 已关闭都继续下一轮
      self = weak.lock();
      if(!self || self->shutting_down || !self->kad) co_return;   // Session 已析构/正在关闭
    }
  }

  TaskSnapshot snapshot(const TaskEntry& t) const {
    TaskSnapshot s;
    s.id = t.id; s.name = t.link.name; s.hash = t.link.hash;
    s.total_size = t.link.size; s.bytes_done = t.bytes_done; s.speed_bps = t.speed_bps;
    s.known_sources = t.known_sources; s.state = t.state; s.error = t.error;
    s.out_path = t.out_path;
    return s;
  }
};

Session::Session(net::IoRuntime& rt, SessionConfig cfg)
  : impl_(std::make_shared<Impl>(rt, std::move(cfg))) {
  asio::co_spawn(rt.context(), Impl::sampler(impl_->weak_from_this()), asio::detached);
  if(impl_->kad){
    // nodes.dat 不存在/解析失败(首次运行/损坏)时 seeds 为空; Impl::kad_run 内部的 bootstrap()
    // 对空 seeds 会快速返回失败, 不阻塞 Session 可用, 随后仍进入 serve_once 常驻循环。
    std::vector<kad::Contact> seeds;
    auto nodes_bytes = read_file_bytes(impl_->cfg.data_dir / "nodes.dat");
    if(auto parsed = kad::parse_nodes_dat(nodes_bytes)) seeds = std::move(*parsed);
    asio::co_spawn(rt.context(), Impl::kad_run(impl_->weak_from_this(), std::move(seeds)), asio::detached);
  }
}

Session::~Session(){ shutdown(); }

void Session::shutdown() noexcept {
  if(!impl_ || impl_->shutting_down) return;   // 幂等: shutting_down 已 true 时不重复处理
  impl_->shutting_down = true;
  for(auto& [id, t] : impl_->tasks) if(t.stop) *t.stop = true;
  // I2: 主动关闭服务器 socket, 促使挂起在 connect_server 初始快照窗口(或前台请求 search/
  // get_sources 等)里的 recv 尽快以错误唤醒返回, 不必等到超时 Impl 才被释放。这里只调用
  // close()(而非完整的 disconnect_server_internal()): shutdown() 是 noexcept 且在析构路径上
  // 被调用, 不适合在此处 emit 事件(调用用户 handler 可能抛出)。
  if(impl_->login) impl_->login->conn.close();
  // 同理关闭 Kad UDP socket, 促使 kad_run 里挂起的 bootstrap/serve_once recv 尽快因 socket
  // 已关闭而返回错误(而非等到超时); 随后落盘当前路由表联系人到 nodes.dat, 供下次启动做种子
  // 引导。persist_nodes_dat 内部已用 std::error_code/spdlog::warn 处理失败, 不抛异常, 满足
  // shutdown() 的 noexcept 约束。
  if(impl_->kad){
    impl_->kad->close();
    impl_->persist_nodes_dat();
  }
}

std::uint64_t Session::add_download(const Ed2kFileLink& link, const std::filesystem::path& save_dir){
  if(link.size == 0 || link.name.empty()) return 0;
  TaskEntry t;
  t.id = impl_->next_id++;
  t.link = link;
  t.out_path = save_dir / link.name;
  auto id = t.id;
  impl_->tasks.emplace(id, std::move(t));
  impl_->emit(TaskStateEvent{id, TaskState::queued, {}});
  impl_->pump();
  return id;
}

bool Session::pause(std::uint64_t id){
  auto it = impl_->tasks.find(id);
  if(it == impl_->tasks.end()) return false;
  auto& t = it->second;
  // 尚未启动的排队任务直接改状态即可, 无需置停标志
  if(t.state == TaskState::queued){ impl_->set_state(t, TaskState::paused); return true; }
  if(t.state != TaskState::connecting && t.state != TaskState::downloading) return false;
  if(t.stop) *t.stop = true;         // 通知 run_task/下载协程尽快退出(errc::cancelled 分支不覆盖终态)
  t.speed_bps = 0;
  impl_->set_state(t, TaskState::paused);
  return true;
}

bool Session::resume(std::uint64_t id){
  auto it = impl_->tasks.find(id);
  if(it == impl_->tasks.end()) return false;
  auto& t = it->second;
  if(t.state != TaskState::paused && t.state != TaskState::failed) return false;
  ++t.generation;                       // 旧代协程若仍在收尾, 其回写全部作废
  t.stop.reset();
  t.error = {};
  t.last_sample_time = {};
  t.last_sample_bytes = t.bytes_done;
  impl_->set_state(t, TaskState::queued);
  impl_->pump();
  return true;
}

bool Session::cancel(std::uint64_t id, bool remove_files){
  auto it = impl_->tasks.find(id);
  if(it == impl_->tasks.end()) return false;
  auto& t = it->second;
  // 用"是否有在途协程"而非可见状态判断: paused 态旧协程可能仍未排空(仍占着文件句柄),
  // 若只看 state==connecting/downloading 会误判 paused 为"已停"。用 Impl 级计数(而非
  // TaskEntry 布尔)是因为 pause→resume 竞态下同一 id 可能有新旧两代协程同时在途,
  // 布尔会被后到的一代覆盖导致误判; 计数能正确反映"是否所有代都已退出"。
  const bool has_inflight = (impl_->inflight.count(id) && impl_->inflight[id] > 0);
  if(t.stop) *t.stop = true;
  impl_->set_state(t, TaskState::cancelled);
  if(remove_files){
    std::vector<std::filesystem::path> files{
      t.out_path,
      std::filesystem::path(t.out_path.string() + ".part.met")};
    if(has_inflight){
      impl_->pending_remove[id] = std::move(files);      // 协程退出后删(此刻句柄未释放)
    } else {
      for(const auto& p : files){ std::error_code ec; std::filesystem::remove(p, ec); }
    }
  }
  impl_->tasks.erase(it);
  return true;
}

std::optional<TaskSnapshot> Session::query(std::uint64_t id) const {
  auto it = impl_->tasks.find(id);
  if(it == impl_->tasks.end()) return std::nullopt;
  return impl_->snapshot(it->second);
}

std::vector<TaskSnapshot> Session::query_all() const {
  std::vector<TaskSnapshot> out;
  out.reserve(impl_->tasks.size());
  for(const auto& [id, t] : impl_->tasks) out.push_back(impl_->snapshot(t));
  return out;
}

void Session::set_event_handler(std::function<void(const SessionEvent&)> handler){
  impl_->handler = std::move(handler);
}

asio::awaitable<tl::expected<server::LoginResult, std::error_code>>
Session::connect_server(std::optional<app::ServerTarget> target){
  // UAF 修复: 本方法跨越多次 co_await(login_with_rotation + 快照窗口内的多轮 receive_events),
  // 若中途 Session 被销毁(如调用方 quit/切账号), 隐式捕获的 this 会在挂起恢复后变成悬垂指针。
  // 与 run_task/sampler 同构: 只经 weak_ptr 访问 Impl, 每个 co_await 之后都重新 lock() 并判空;
  // lock() 成功期间 self 持有一份额外的 shared_ptr 引用, 足以让 Impl(及其里面的连接)在本协程
  // 收尾前不被析构, 即使 Session 本体已经先行销毁。
  auto weak = impl_->weak_from_this();
  auto self = weak.lock();
  if(!self) co_return tl::unexpected(make_error_code(errc::cancelled));   // 理论上入口处必然存活, 仅防御
  self->disconnect_server_internal();      // 先清掉旧连接(幂等), 保证只有一个存活连接
  // I1: 在挂起(co_await login_with_rotation)之前就占用本次连接尝试的代次。若挂起期间又有
  // 一次更晚的 connect_server()/disconnect_server() 调用抢先执行, 它会继续推进
  // server_generation; 本次恢复后发现代次已不匹配, 即可判定"被抢先", 从而丢弃自己刚建立的
  // 连接而不覆盖 self->login, 避免两次并发 connect_server 都各自 std::move 进 login 导致
  // 静默丢弃前一个连接、绕过"先 close 再 reset"的次序。
  const auto gen = ++self->server_generation;
  auto ex = self->rt.executor();
  auto lg = co_await app::login_with_rotation(ex, self->server_met_bytes,
                                              target ? target : self->cfg.server_override,
                                              self->login_params(), self->cfg.per_server_timeout);
  self = weak.lock();
  if(!self || self->shutting_down) co_return tl::unexpected(make_error_code(errc::cancelled));
  if(self->server_generation != gen){
    // 本次尝试已被更晚的调用抢先: 关闭刚建立的连接(若登录成功), 不写入 login, 直接返回。
    if(lg) lg->conn.close();
    co_return tl::unexpected(make_error_code(errc::cancelled));
  }
  if(!lg) co_return tl::unexpected(lg.error());
  auto result = lg->result;                 // 先取值, 避免 move 之后再读悬空成员
  self->login = std::move(*lg);

  self->server_state = ServerStateEvent{};
  self->server_state.connected = true;
  self->server_state.high_id = result.high_id;
  // C2: 这里的 ip/port 只是"请求连接的目标"占位值——login_with_rotation 内部会在该目标失败时
  // 故障转移到 server.met/内建 fallback 里的其它服务器, 实际连上的可能是另一个地址。真正权威
  // 的地址以下面 on_event 收到的 ServerIdentEvent(服务器自报的 ip/port/name)为准并会覆盖。
  if(target){ self->server_state.ip = target->ip; self->server_state.port = target->port; }
  else if(self->cfg.server_override){
    self->server_state.ip = self->cfg.server_override->ip;
    self->server_state.port = self->cfg.server_override->port;
  }

  // ServerStatusEvent(users/files) 与 ServerIdentEvent(name+ip+port, 服务器自报的真实身份)
  // 合并进 server_state 并转发为 SessionEvent。回调本身已经是 weak_ptr 驱动(与本方法体无关的
  // 独立生命周期), 直接复用上面拿到的 weak, 不必再派生一次。
  self->snapshot_ident_seen = false;
  self->server_sub = self->login->conn.on_event(
    [weak](const server::ServerEvent& ev){
      auto s = weak.lock();
      if(!s) return;
      if(auto* status = std::get_if<server::ServerStatusEvent>(&ev)){
        s->server_state.users = status->users;
        s->server_state.files = status->files;
        s->emit(s->server_state);
      } else if(auto* ident = std::get_if<server::ServerIdentEvent>(&ev)){
        s->server_state.name = ident->name;
        s->server_state.ip = ident->ip;      // C2: 用服务器自报地址覆盖占位的 target/override
        s->server_state.port = ident->port;
        s->snapshot_ident_seen = true;
        s->emit(s->server_state);
      }
    });

  self->emit(self->server_state);   // 先 emit 一次 connected=true(占位地址), 让调用方尽快感知已连接

  // 方案 C: 不再启动常驻 receive_loop——Task 6 的常驻推送监听与 search()/get_sources() 等前台
  // 请求共用同一条连接时会并发调用 conn.recv(), 而 asio 不允许对同一 socket 并发发起读操作;
  // 曾尝试用 owner/waiter 解复用修复(见历史提交), 但 Opus 审查发现服务器掉线时挂起的等待者
  // 会在已析构对象上恢复(UAF), 且 eD2k 响应帧不带请求 ID, 并发同 opcode 请求会互相错投。
  // 根治方式是回到"单读者"模型: 一条连接任意时刻至多一个协程读取。
  // 因此这里只在 login 成功后同步读一个短窗口(<= per_server_timeout 且 <= 2s), 尽量捕获服务器
  // 紧跟着 login 应答(IDCHANGE)发来的 SERVERSTATUS/SERVERIDENT 初始快照(经上面的 on_event
  // 合并进 server_state 并各自触发一次 emit); 拿到 SERVERIDENT(真实身份)后可提前结束, 否则
  // 读满窗口预算即停。窗口结束后连接转入空闲(无任何协程持续读取), 之后 search()/get_sources()
  // 等前台请求可安全独占读取该连接, 无需任何并发协调。
  // 已知降级(方案 C 的取舍): 窗口结束后服务器再推送的状态更新不会被感知; 也不再主动检测服务器
  // 掉线, 只有在下一次前台请求(如 search)因连接已断而失败时才会发现。
  const auto snapshot_budget = std::min(self->cfg.per_server_timeout, std::chrono::milliseconds(2000));
  const auto snapshot_deadline = std::chrono::steady_clock::now() + snapshot_budget;
  for(;;){
    if(self->shutting_down || self->server_generation != gen || !self->login)
      co_return tl::unexpected(make_error_code(errc::cancelled));   // 被更晚的调用抢先/正在关闭, 让出
    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(
      snapshot_deadline - std::chrono::steady_clock::now());
    if(rem.count() <= 0) break;                // 窗口预算耗尽, 结束快照读取
    auto r = co_await self->login->conn.receive_events(rem);
    self = weak.lock();
    if(!self || self->shutting_down || self->server_generation != gen || !self->login)
      co_return tl::unexpected(make_error_code(errc::cancelled));
    if(!r) break;                              // 超时或本轮无更多推送: 结束窗口(login 已成功, 不因此判定断线)
    if(self->snapshot_ident_seen) break;        // 已拿到服务器自报的真实身份, 无需再等
  }
  co_return result;
}

void Session::disconnect_server(){
  impl_->disconnect_server_internal();
}

bool Session::server_connected() const {
  return impl_->login.has_value();
}

std::vector<ServerInfo> Session::server_list() const {
  std::vector<ServerInfo> out;
  out.reserve(impl_->servers.servers.size());
  const bool connected = impl_->login.has_value() && impl_->server_state.connected;
  for(const auto& e : impl_->servers.servers){
    ServerInfo info;
    info.ip = e.ip; info.port = e.port; info.name = e.name;
    info.connected = connected && impl_->server_state.ip == e.ip && impl_->server_state.port == e.port;
    out.push_back(std::move(info));
  }
  return out;
}

bool Session::add_server(IPv4 ip, std::uint16_t port, const std::string& name){
  auto& list = impl_->servers.servers;
  bool exists = std::any_of(list.begin(), list.end(),
    [&](const ServerEntry& e){ return e.ip == ip && e.port == port; });
  if(exists) return false;
  ServerEntry e; e.ip = ip; e.port = port; e.name = name;
  list.push_back(std::move(e));
  impl_->persist_server_met();
  return true;
}

bool Session::remove_server(IPv4 ip, std::uint16_t port){
  auto& list = impl_->servers.servers;
  auto it = std::find_if(list.begin(), list.end(),
    [&](const ServerEntry& e){ return e.ip == ip && e.port == port; });
  if(it == list.end()) return false;
  list.erase(it);
  impl_->persist_server_met();
  return true;
}

asio::awaitable<tl::expected<std::size_t, std::error_code>>
Session::update_server_met(const std::string& url){
  // UAF 修复: 同 connect_server/search——co_await dl.fetch(...) 期间 Session 可能被销毁,
  // 改为 weak_ptr 驱动, co_await 之后重新 lock() 才能安全访问 Impl。
  auto weak = impl_->weak_from_this();
  auto self = weak.lock();
  if(!self) co_return tl::unexpected(make_error_code(errc::cancelled));
  std::error_code ec;
  std::filesystem::create_directories(self->cfg.data_dir, ec);
  auto tmp_path = self->cfg.data_dir / "server_met_download.tmp";
  infra::HTTPDownload dl(self->rt.executor());
  auto fr = co_await dl.fetch(url, tmp_path, std::chrono::seconds(30));
  self = weak.lock();
  if(!self) co_return tl::unexpected(make_error_code(errc::cancelled));
  if(!fr) co_return tl::unexpected(fr.error());

  auto bytes = read_file_bytes(tmp_path);
  std::filesystem::remove(tmp_path, ec);
  auto parsed = parse_server_met(bytes);
  if(!parsed) co_return tl::unexpected(parsed.error());

  auto key = [](IPv4 ip, std::uint16_t port){ return (std::uint64_t(ip.host()) << 16) | port; };
  std::unordered_set<std::uint64_t> seen;
  seen.reserve(self->servers.servers.size());
  for(const auto& e : self->servers.servers) seen.insert(key(e.ip, e.port));

  std::size_t added = 0;
  for(auto& e : parsed->servers){
    if(seen.insert(key(e.ip, e.port)).second){
      self->servers.servers.push_back(std::move(e));
      ++added;
    }
  }
  if(added > 0) self->persist_server_met();
  co_return added;
}

asio::awaitable<tl::expected<std::vector<server::SearchResultItem>, std::error_code>>
Session::search(const std::string& keyword, const SearchFilters& filters){
  // UAF 修复: 与 connect_server 同理——co_await conn.search(...) 期间若 Session 被销毁, 隐式
  // 捕获的 this 会在挂起恢复后悬垂。改为 weak_ptr 驱动: 入口 lock 一次拿到 self(其持有的额外
  // shared_ptr 引用保证 Impl/连接在本协程收尾前存活), co_await 之后再 lock 一次才能安全返回。
  auto weak = impl_->weak_from_this();
  auto self = weak.lock();
  if(!self || self->shutting_down || !self->login)
    co_return tl::unexpected(make_error_code(errc::connect_failed));
  // 按 filters 逐项用 operator& 组合进 SearchExpr; 只在非默认值时才追加对应子表达式。
  server::SearchExpr expr = server::Keyword{keyword};
  if(filters.type != server::FileType::Any)
    expr = std::move(expr) & server::SearchExpr(server::TypeIs{filters.type});
  if(filters.min_size > 0)
    expr = std::move(expr) & server::SearchExpr(server::SizeAtLeast{filters.min_size});
  if(filters.min_avail > 0)
    expr = std::move(expr) & server::SearchExpr(server::AvailAtLeast{filters.min_avail});
  const auto timeout = self->cfg.per_server_timeout;
  auto r = co_await self->login->conn.search(expr, timeout);
  self = weak.lock();
  if(!self) co_return tl::unexpected(make_error_code(errc::cancelled));
  co_return r;
}

Session::KadStatus Session::kad_status() const {
  return KadStatus{impl_->kad != nullptr,
                    impl_->kad ? impl_->kad->routing_table().size() : std::size_t{0}};
}

}
