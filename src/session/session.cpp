#include "ed2k/session/session.hpp"
#include <algorithm>
#include <cstring>
#include <exception>
#include <fstream>
#include <map>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include "ed2k/download/download.hpp"
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
  // cancel(remove_files=true) 在任务运行中被调用时, 文件此刻仍被 PartFile 打开(Windows 删除会失败);
  // 删除动作先记录到此处, 待协程退出(句柄已释放)后由 on_task_coroutine_exit 执行。键 = 任务 id。
  std::map<std::uint64_t, std::vector<std::filesystem::path>> pending_remove;
  // 按任务 id 统计在途 run_task 协程数, 跨代累计(不放 TaskEntry: cancel() erase 任务后仍需保留计数)。
  // pause→resume 竞态下同一 id 可能有新旧两代协程并存(旧代挂起未醒, 新代已 pump 启动),
  // 用布尔标记无法表达"多个在途"这一状态, 必须用计数; 只有归零(最后一个持句柄的协程退出)才安全删文件。
  std::map<std::uint64_t, int> inflight;

  Impl(net::IoRuntime& rt_arg, SessionConfig cfg_arg)
    : rt(rt_arg), cfg(std::move(cfg_arg)) {
    server_met_bytes = read_file_bytes(cfg.data_dir / "server.met");
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
    p.user_hash = cfg.user_hash.value_or(*UserHash::from_hex("0123456789abcdeffedcba9876543210"));
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
}

Session::~Session(){ shutdown(); }

void Session::shutdown() noexcept {
  if(!impl_ || impl_->shutting_down) return;
  impl_->shutting_down = true;
  for(auto& [id, t] : impl_->tasks) if(t.stop) *t.stop = true;
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

}
