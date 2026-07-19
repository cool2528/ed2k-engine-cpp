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
  // 启用 Kad(DHT) 子系统: 用 data_dir/nodes.dat 做种子引导, 维护路由表并可被其它 Kad 节点发现,
  // shutdown 时把当前路由表落盘回 nodes.dat。当前不接入下载增源(find_sources) ——
  // 该功能会与 Kad 常驻的单读者 socket 争抢同一连接, 留待后续专项任务实现; 见 kad_status()。
  // kad_udp_port 端口绑定失败(如已被其它 Kad 客户端占用)时自动降级为不启用, 不影响 Session
  // 其余功能; kad_status().running 会反映实际是否成功启用。
  bool enable_kad = false;
  std::uint16_t kad_udp_port = 4672;    // Kad UDP 监听端口; 0 = 系统分配
};

struct TaskStateEvent { std::uint64_t task_id = 0; TaskState state = TaskState::queued; std::error_code error; };

struct ServerInfo {                      // UI 服务器列表行
  IPv4 ip; std::uint16_t port = 0;
  std::string name;                      // 来自 server.met tags 或 IDENT, 可为空
  bool connected = false;
};
struct ServerStateEvent {                // 服务器连接状态变化事件
  bool connected = false;
  IPv4 ip; std::uint16_t port = 0;
  std::string name;
  bool high_id = false;
  std::uint32_t users = 0, files = 0;
};
using SessionEvent = std::variant<TaskStateEvent, ServerStateEvent>;

// search() 过滤条件: 类型/最小大小/最少源数, 均为 0/Any 表示不限, 按需组合进 SearchExpr。
struct SearchFilters {
  server::FileType type = server::FileType::Any;
  std::uint64_t min_size = 0;   // 字节; 0 = 不限
  std::uint32_t min_avail = 0;  // 最少源数; 0 = 不限
};

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

  // 服务器管理: 连接状态 + 列表维护 + server.met 持久化。所有方法必须在网络线程调用。
  // target 为空时按 cfg.server_override + server.met + 内建 fallback 轮换登录。
  // 方案 C 降级(见 session.cpp 实现注释): 登录成功后仅同步读一个短窗口(<= 2s)捕获服务器初始
  // 推送快照(SERVERSTATUS/SERVERIDENT), 窗口结束后连接转入空闲——不再有常驻读者。因此窗口结束
  // 后服务器再推送的状态更新不会被感知, 也不再主动检测服务器掉线, 只有下一次前台请求(如
  // search)因连接已失效而失败时才会发现。
  boost::asio::awaitable<tl::expected<server::LoginResult, std::error_code>>
    connect_server(std::optional<app::ServerTarget> target);
  void disconnect_server();                                       // 幂等; 未连接时 no-op
  bool server_connected() const;
  std::vector<ServerInfo> server_list() const;
  bool add_server(IPv4 ip, std::uint16_t port, const std::string& name);   // 去重; 落盘 server.met
  bool remove_server(IPv4 ip, std::uint16_t port);                          // 落盘 server.met
  // 从 url 下载 server.met, 按 (ip,port) 去重合并进当前列表并落盘, 返回新增条数。
  boost::asio::awaitable<tl::expected<std::size_t, std::error_code>>
    update_server_met(const std::string& url);

  // 搜索: 关键词 + 类型/大小/源数过滤。需已 connect_server, 否则返回 errc::connect_failed。
  boost::asio::awaitable<tl::expected<std::vector<server::SearchResultItem>, std::error_code>>
    search(const std::string& keyword, const SearchFilters& filters);

  // Kad(DHT) 状态: running 反映 cfg.enable_kad 是否生效(网络对象是否已构造), contacts 为路由表
  // 当前联系人数。cfg.enable_kad=false 时恒为 {false, 0}。
  struct KadStatus { bool running = false; std::size_t contacts = 0; };
  KadStatus kad_status() const;
 private:
  struct Impl;
  std::shared_ptr<Impl> impl_;   // 协程持 weak_ptr, Session 销毁后挂起协程安全退化
};

}
