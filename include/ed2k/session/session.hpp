#pragma once
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/export.hpp"
#include "ed2k/link/ed2k_link.hpp"
#include "ed2k/net/runtime.hpp"
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/app/server_session.hpp"

namespace ed2k::session {

enum class TaskState { queued, connecting, downloading, paused, completed, failed, cancelled };

struct TaskSnapshot {
  std::uint64_t id = 0;
  std::string name;
  FileHash hash;
  std::uint64_t total_size = 0;
  std::uint64_t bytes_done = 0;
  std::uint64_t speed_bps = 0;
  std::size_t known_sources = 0;
  TaskState state = TaskState::queued;
  std::error_code error;
  std::filesystem::path out_path;
};

struct SessionConfig {
  std::string nickname = "ed2k";
  std::uint16_t tcp_port = 4662;
  std::filesystem::path data_dir;                    // server.met 等数据目录
  std::size_t max_concurrent_tasks = 3;
  peer::ObfuscationPolicy obfuscation = peer::ObfuscationPolicy::disabled;
  std::optional<UserHash> user_hash;
  std::optional<app::ServerTarget> server_override;  // 测试/设置注入的优先服务器
  std::chrono::milliseconds per_server_timeout = std::chrono::seconds(30);
  std::chrono::milliseconds task_io_timeout = std::chrono::seconds(60);  // 每次网络操作超时(非总时长)
};

struct TaskStateEvent { std::uint64_t task_id = 0; TaskState state = TaskState::queued; std::error_code error; };
using SessionEvent = std::variant<TaskStateEvent>;

// GUI 友好的任务管理门面: 任务注册表 + 下载编排协程 + 并发调度 + 1s 速度采样 + 状态事件。
// 契约: 所有公共方法必须在网络线程(rt.executor())上调用; 内部状态无 mutex/condition_variable。
class ED2K_EXPORT Session {
 public:
  Session(net::IoRuntime& rt, SessionConfig cfg);
  ~Session();
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;
  // 契约: 所有方法必须在网络线程(rt.executor())上调用
  std::uint64_t add_download(const Ed2kFileLink& link, const std::filesystem::path& save_dir);
  bool pause(std::uint64_t id);                       // queued/connecting/downloading → paused
  bool resume(std::uint64_t id);                      // paused/failed → queued(重新排队, .part.met 续传)
  bool cancel(std::uint64_t id, bool remove_files);   // 任意态 → 移除任务; remove_files 删数据+met(延迟到协程退出后)
  std::optional<TaskSnapshot> query(std::uint64_t id) const;
  std::vector<TaskSnapshot> query_all() const;
  void set_event_handler(std::function<void(const SessionEvent&)> handler);
  void shutdown() noexcept;   // 置停全部任务; 幂等; 析构自动调用
 private:
  struct Impl;
  std::shared_ptr<Impl> impl_;   // 协程持 weak_ptr, Session 销毁后挂起协程安全退化
};

}
