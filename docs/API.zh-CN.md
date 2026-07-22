# API 概览

[English](API.md)

公共 API 位于 `include/ed2k/` 下。所有网络 API 都是 Boost.Asio 协程
（可使用 `co_await`，返回 `awaitable<T>`）；引擎运行在单个 `io_context` / 单个网络
线程上（参见 README → 架构）。错误处理使用 `tl::expected<T, std::error_code>`。

## 使用已安装的 CMake 包

消费者需要 C++20，并链接导出的 `ed2k::core` 目标：

```cmake
cmake_minimum_required(VERSION 3.24)
project(app LANGUAGES CXX)

find_package(ed2k 2.2 CONFIG REQUIRED)

add_executable(app main.cpp)
target_compile_features(app PRIVATE cxx_std_20)
target_link_libraries(app PRIVATE ed2k::core)
```

使用 `cmake --install <build-dir> --prefix <install-prefix>` 安装 ed2k 后，请在配置消费者
项目时将 `<install-prefix>` 加入 `CMAKE_PREFIX_PATH`。导出包不会捆绑其依赖：
`spdlog`、`tl-expected`、Zlib、OpenSSL、Boost.Asio 和 Threads 也必须能够通过
vcpkg/工具链设置或依赖前缀被发现。

Push 和拉取请求 CI 会在 Windows 和 Ubuntu 上运行 Debug 与 Release。每个作业都会执行
配置、构建、测试、安装，以及独立消费者的配置/构建/运行。实时测试仍为选择性启用，
不会阻塞该 CI 矩阵。

## `ed2k/net` — 运行时与传输

```cpp
namespace ed2k::net {
class IoRuntime {
 public:
  boost::asio::any_io_executor executor();          // 网络线程执行器（io_context）
  boost::asio::any_io_executor disk_executor();     // 磁盘 I/O 线程池（thread_pool{1}）
  void run(); void restart(); void stop();
  boost::asio::io_context& context();
  template<class F> void co_spawn_detached(F&&);    // 在网络线程上运行协程
};
}
```
- `executor()` — 用于所有网络工作（服务器/对等端套接字、协程）。
- `disk_executor()` — 注入 `MultiSourceDownload::set_disk_executor`，以卸载写入操作。
- `connection.hpp` / `framing.hpp` / `packet.hpp` — TCP 帧编码/解码（eDonkey + eMule
  协议字节），`Packet{protocol, opcode, payload}`。

## `ed2k/hash` — 哈希

```cpp
enum class HashVariant { Blue, Red };
struct HashResult { FileHash file_hash; std::vector<PartHash> part_hashes; };
HashResult hash_bytes(std::span<const std::byte>, HashVariant = HashVariant::Red);
tl::expected<HashResult, std::error_code> hash_file(const std::filesystem::path&, HashVariant = HashVariant::Red);
tl::expected<AICHHash, std::error_code> aich_hash_file(const std::filesystem::path&);  // 两级 Merkle 根
```
- `aich_hash_bytes`（位于 `aich_hasher.hpp`）构建与 aMule `SHAHashSet` 匹配、按分块组织的
  两级 Merkle 树（常量 `PART_SIZE`=9,728,000，`AICH_BLOCK_SIZE`=184,320）。

## `ed2k/core/hash.hpp` — 哈希类型

```cpp
using FileHash = MD4Hash; using UserHash = MD4Hash; using PartHash = MD4Hash;   // 16 字节
class MD4Hash  { static tl::expected<MD4Hash,std::error_code> from_hex(std::string_view); std::string to_hex() const; };
class AICHHash { /* 20 字节 */ std::string to_base32() const; };
struct IPv4 { static std::optional<IPv4> from_dotted(std::string_view); std::string to_dotted() const; };
```

## `ed2k/link/ed2k_link.hpp` — 链接解析

```cpp
struct Ed2kFileLink { std::string name; std::uint64_t size; FileHash hash; std::optional<AICHHash> aich; std::vector<SourceEndpoint> sources; };
struct ServerLink    { IPv4 ip; std::uint16_t port; };
struct ServerListLink{ std::string url; };
using Ed2kLink = std::variant<Ed2kFileLink, ServerLink, ServerListLink>;
tl::expected<Ed2kLink, std::error_code> parse_link(std::string_view);
std::string to_string(const Ed2kFileLink&);
```

## `ed2k/metfile` — 元数据文件

```cpp
// server.met
tl::expected<ServerMet, std::error_code> parse_server_met(std::span<const std::byte>);
// .part.met（aMule 0xE0/0xE2 格式；仍可解析旧版内部 gap 二进制数据）
struct PartFileState { FileHash hash; std::vector<PartHash> part_hashes; std::vector<std::pair<std::uint64_t,std::uint64_t>> gaps; };
tl::expected<PartFileState, std::error_code> parse_part_met(std::span<const std::byte>);
std::vector<std::byte> write_part_met(const PartFileState&);
```

## `ed2k/server` — 服务器会话

```cpp
namespace ed2k::server {
struct LoginParams { std::string nickname; std::uint16_t client_port; UserHash user_hash; /* ... */ };
struct LoginResult { std::uint32_t client_id; bool high_id; std::uint32_t flags; };
class ServerConnection {
  awaitable<expected<LoginResult,    ec>> login(LoginParams, milliseconds);
  awaitable<expected<std::vector<SearchResult>, ec>> search(Keyword, milliseconds);
  awaitable<expected<SourceSet, ec>> get_sources(FileHash, std::uint64_t size, milliseconds);
};
}
```

## `ed2k/download` — 下载引擎

```cpp
class PartFile {
 public:
  PartFile(const std::filesystem::path&, std::uint64_t size, const FileHash&, std::vector<PartHash>);
  tl::expected<void, ec> write_block(std::uint64_t start, std::uint64_t end, std::span<const std::byte>);
  awaitable<tl::expected<void, ec>> write_block_async(std::uint64_t start, std::uint64_t end,
                                                      std::span<const std::byte>, boost::asio::any_io_executor disk_ex);
  bool complete() const noexcept;
  std::vector<std::pair<std::uint64_t,std::uint64_t>> gaps() const;
  bool is_block_done(std::size_t part, std::size_t block_in_part) const noexcept;
};

class BlockAllocator {  // 按分块组织的块模型；块绝不会跨越分块边界
 public:
  BlockAllocator(std::uint64_t size, const std::vector<PartHash>&, std::optional<AICHHash> root);
  std::optional<std::tuple<std::size_t part, std::size_t bip, std::uint64_t start, std::uint64_t end>> next_block();
  std::optional<...> next_block_for_parts(const std::vector<bool>& has_part);  // raccoon：按对等端已有分块筛选
  bool mark_block_done(std::size_t part, std::size_t bip);
  void requeue_block(std::size_t part, std::size_t bip);
};

class MultiSourceDownload {
 public:
  class Builder {
   public:
    Builder& sources(std::vector<server::SourceEndpoint>);
    Builder& server(server::ServerConnection&);
    Builder& listener(peer::InboundListener&);
    Builder& kad_network(kad::KadNetwork&);              // 可选的 Kad 来源扩充
    Builder& kad_peers(std::vector<kad::Contact>);       // 与 kad_network 搭配使用, 必填(B4, 见下文)
    Builder& disk_executor(boost::asio::any_io_executor);
    MultiSourceDownload build();
  };
  void set_disk_executor(boost::asio::any_io_executor);  // 注入磁盘池（默认值 = 网络执行器）
  awaitable<expected<void, ec>> run(milliseconds total_timeout, std::size_t n_workers);
};
```

注入 `KadNetwork` 后，`MultiSourceDownload::run` 会调用 `find_sources(kad_peers, ...)`，并在现有
多来源设置循环之前追加直接 Kad 来源结果——**不会**读取 `kad_network` 自己的路由表。`kad_peers`
必须由调用方显式填入(从真正持有联系人的路由表快照而来)，这样 `kad_network` 就可以是一个自己
路由表为空的一次性 ephemeral 实例(如 `udp_port=0`、独立 socket)——当已有一个常驻 Kad 实例正被
另一个协程读取时(单读者约束；见 `session.cpp` 中的 `Session::run_task`：它从常驻的 `kad` 成员
快照 peers，再用一个全新的 ephemeral `KadNetwork` 发起查询，而不是复用常驻 socket)，这正是所
需要的方式。`kad_peers` 为空时整段 Kad 分支会被跳过，效果与不设置 `kad_network` 相同。
服务器来源仍具有最高优先级；Kad 仅用于扩充候选列表。

## `ed2k/kad` — Kademlia DHT

```cpp
namespace ed2k::kad {
class KadID { static tl::expected<KadID, ec> from_hex(std::string_view); std::string to_hex() const; };
struct Contact { KadID id; IPv4 ip; std::uint16_t udp_port, tcp_port; std::uint8_t version; };
struct KadSearchEntry { KadID answer_id; std::vector<codec::Tag> tags; };

class KadNetwork {
 public:
  awaitable<expected<void, ec>> bootstrap(std::span<const Contact>, milliseconds);
  awaitable<expected<std::vector<KadSearchEntry>, ec>>
    search_keyword(std::span<const Contact>, KadID key_id, milliseconds);
  awaitable<expected<std::vector<KadSearchEntry>, ec>>
    find_sources(std::span<const Contact>, KadID file_id, std::uint64_t file_size, milliseconds);
  awaitable<expected<KadPublishResponse, ec>>
    publish_source(const Contact&, KadID file_id, const KadSearchEntry&, milliseconds);
  RoutingTable& routing_table();
};

std::vector<std::byte> write_nodes_dat(std::span<const Contact>);
tl::expected<std::vector<Contact>, ec> parse_nodes_dat(std::span<const std::byte>);
std::optional<IPv4> source_ip(const KadSearchEntry&);
std::uint16_t source_tcp_port(const KadSearchEntry&);
}
```

## `ed2k/app/server_session.hpp` — 高层编排

```cpp
namespace ed2k::app {
struct ServerTarget { IPv4 ip; std::uint16_t port; };
struct DownloadOpts {
  std::filesystem::path out_path;
  std::chrono::milliseconds per_server_timeout = std::chrono::seconds(30);
  std::chrono::milliseconds total_timeout = std::chrono::seconds(120);
  std::uint16_t client_port = 4662;   // InboundListener 端口（LowID 回调）
  std::optional<std::reference_wrapper<kad::KadNetwork>> kad_network;
};
awaitable<expected<LoginSession, ec>>
  login_with_rotation(any_io_executor, std::span<const std::byte> server_met,
                      std::optional<ServerTarget> override, const LoginParams&, milliseconds per_server);
awaitable<expected<void, ec>>
  download_link(any_io_executor, const Ed2kFileLink&, std::span<const std::byte> server_met,
                std::optional<ServerTarget> override, const DownloadOpts&);
}
```
`download_link` 的流程为：登录 → `get_sources` → 仅在存在 LowID 来源时构造
`InboundListener`（否则只直接连接 HighID）→ 设置 `DownloadOpts::kad_network` 时选择性地
追加 Kad 直接来源（peers 从该 `kad_network` 自己的路由表通过 `closest_to` 快照后, 传给上文
`MultiSourceDownload::Builder` 的 `kad_peers`）→ `MultiSourceDownload(...).run(total_timeout, 3)`。

## `ed2k/infra/http_download.hpp` — 经验证的 HTTP(S) 下载

```cpp
struct HTTPDownloadOptions { std::optional<std::filesystem::path> additional_ca_file; };
class HTTPDownload {
 public:
  explicit HTTPDownload(boost::asio::any_io_executor, HTTPDownloadOptions = {});
  awaitable<tl::expected<void, std::error_code>>
    fetch(const std::string& url, const std::filesystem::path& destination,
          std::chrono::milliseconds timeout);
};
```

`fetch` 接受 HTTP 和 HTTPS，验证 HTTPS 证书链和主机名，且不提供不安全的
验证绕过方式。它在同一个总体截止时间内最多跟随五次重定向，该截止时间覆盖
所有网络和 TLS 操作。允许 HTTP 重定向到 HTTPS，但拒绝 HTTPS 降级重定向到 HTTP。

任何 2xx 状态（包括 `206 Partial Content`）只有在包含有效 `Content-Length` 时才会被接受。
不支持 chunked 和以连接关闭为结束标志的响应体。完整的已声明响应体会先写入临时文件并刷盘，
再以原子方式安装到 `destination`；在不支持目录 fsync 的平台上，父目录的崩溃持久性
仅为尽力保证。失败时不会公布不完整的响应体。

## `ed2k/share` — 共享、上传与积分

```cpp
namespace ed2k::share {
struct KnownFile {
  FileHash hash;
  AICHHash aich_root;
  std::vector<PartHash> part_hashes;
  std::filesystem::path path;
  std::string name;
  std::uint64_t size;
  std::uint8_t rating;
  std::string comment;
};

class KnownFileDB {
 public:
  tl::expected<void, std::error_code> scan_dir(const std::filesystem::path&);
  void add(KnownFile);
  bool set_file_desc(const FileHash&, std::uint8_t rating, std::string comment);
  const KnownFile* find(const FileHash&) const;
  const std::vector<KnownFile>& files() const noexcept;
};

class UploadSession {
 public:
  UploadSession(boost::asio::ip::tcp::socket&&, KnownFileDB&, peer::HelloInfo,
                boost::asio::any_io_executor disk_executor, UploadQueue* = nullptr,
                UploadBandwidthThrottler* = nullptr, ClientCredits* = nullptr);
  awaitable<expected<void, ec>> run(milliseconds timeout);
};
}
```

`UploadSession` 是上传侧的 C2C 角色：它响应文件名/状态/哈希集/块/AICH 请求，
在提供相应组件时应用队列/限速/积分钩子，响应共享文件和 SX2 请求，并将收到的
`OP_FILEDESC` 评分/评论存储到当前请求的文件中。

`peer::C2CConnection` 还公开了上传/共享辅助接口：

```cpp
awaitable<expected<peer::SourceExchangeAnswer, ec>>
  request_sources2(FileHash, milliseconds timeout);
awaitable<expected<void, ec>>
  send_file_desc(std::uint8_t rating, std::string_view comment);
```

## `ed2k/session` — Session 门面（面向 GUI 嵌入）

`Session` 是上述底层构件之上的 GUI 友好门面：任务注册表、下载编排、并发调度、
1 秒速度采样、服务器/Kad/分享管理，以及单一事件流——桌面客户端所需的一切，
无需直接接触 `MultiSourceDownload`、`ServerConnection` 或 `KadNetwork`。

> **线程契约——使用 `Session` 前必读（以下两条均为强约束，非建议）：**
> 1. **`Session` 的所有公共方法必须在网络线程上调用**，即从运行在
>    `IoRuntime::executor()` 上的协程或回调中调用。`Session` 内部不持有
>    `mutex`/`condition_variable`；从其它线程调用不是"不支持"，而是数据竞争。
> 2. **通过 `set_event_handler` 注册的事件回调同样在网络线程上触发。** GUI
>    集成不得在回调内部直接操作 UI 控件，必须先将事件转投（post/queue）到
>    UI 线程（例如 Qt 的 `QMetaObject::invokeMethod(..., Qt::QueuedConnection)`），
>    再据此更新界面。

```cpp
namespace ed2k::session {

enum class TaskState { queued, connecting, downloading, paused, completed, failed, cancelled };

struct TaskSnapshot {
  std::uint64_t id;
  std::string name;
  FileHash hash;
  std::uint64_t total_size;
  std::uint64_t bytes_done;
  std::uint64_t speed_bps;
  std::size_t known_sources;
  TaskState state;
  std::error_code error;
  std::filesystem::path out_path;
};

struct SessionConfig {
  std::string nickname = "ed2k";
  std::uint16_t tcp_port = 4662;
  std::filesystem::path data_dir;                          // server.met 等数据目录
  std::size_t max_concurrent_tasks = 3;
  peer::ObfuscationPolicy obfuscation = peer::ObfuscationPolicy::disabled;
  std::optional<UserHash> user_hash;
  std::optional<app::ServerTarget> server_override;         // 测试/设置注入的优先服务器
  std::chrono::milliseconds per_server_timeout = std::chrono::seconds(30);
  std::chrono::milliseconds task_io_timeout = std::chrono::seconds(60);
  bool enable_kad = false;                                  // 见下方 Phase 0 已知限制
  std::uint16_t kad_udp_port = 4672;                        // 0 = 由系统分配
};

struct TaskStateEvent { std::uint64_t task_id; TaskState state; std::error_code error; };
struct ServerInfo {
  IPv4 ip; std::uint16_t port; std::string name; bool connected;
  std::uint32_t users;      // 静态值来自 server.met；当前已连接行会被连接期实时值覆盖
  std::uint32_t files;      // 同上
  std::uint32_t max_users;  // 仅 server.met 静态值——没有任何服务器推送会带这个字段
};
struct ServerStateEvent {
  bool connected; IPv4 ip; std::uint16_t port; std::string name;
  bool high_id; std::uint32_t users, files;
};
using SessionEvent = std::variant<TaskStateEvent, ServerStateEvent>;

struct SearchFilters {
  server::FileType type = server::FileType::Any;
  std::uint64_t min_size = 0;    // 字节；0 = 不限
  std::uint32_t min_avail = 0;   // 最少源数；0 = 不限
};

struct SharedFileInfo {
  std::string name; std::filesystem::path path; std::uint64_t size; FileHash hash;
  std::uint64_t uploaded;  // 近似值：只分享单个文件时为会话累计上传字节数的精确值，
                           // 否则为全部分享文件的未拆分汇总（见下方类说明）
};

struct UploadStats { std::size_t active_sessions; std::uint64_t total_uploaded; };

class ED2K_EXPORT Session {
 public:
  Session(net::IoRuntime& rt, SessionConfig cfg);
  ~Session();
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  // 任务生命周期——以下每个方法都必须在 rt.executor() 上运行。
  std::uint64_t add_download(const Ed2kFileLink& link, const std::filesystem::path& save_dir);
  bool pause(std::uint64_t id);                        // queued/connecting/downloading -> paused
  bool resume(std::uint64_t id);                       // paused/failed -> queued（重新进入调度，
                                                         // 从 .part.met 续传）
  bool cancel(std::uint64_t id, bool remove_files);    // 任意状态 -> 移除任务；remove_files 额外
                                                         // 删除数据 + .part.met，延迟到该任务
                                                         // 在途协程完全退出后执行
  std::optional<TaskSnapshot> query(std::uint64_t id) const;
  std::vector<TaskSnapshot> query_all() const;
  void set_event_handler(std::function<void(const SessionEvent&)> handler);
  void shutdown() noexcept;   // 停止全部任务；幂等；析构函数也会调用

  // 服务器管理：连接状态 + 列表维护 + server.met 持久化。
  // target 为 nullopt 时按 cfg.server_override + server.met + 内建 fallback 列表轮换登录。
  boost::asio::awaitable<tl::expected<server::LoginResult, std::error_code>>
    connect_server(std::optional<app::ServerTarget> target);
  void disconnect_server();                            // 幂等；未连接时 no-op
  bool server_connected() const;
  std::vector<ServerInfo> server_list() const;
  bool add_server(IPv4 ip, std::uint16_t port, const std::string& name);      // 去重；落盘
  bool remove_server(IPv4 ip, std::uint16_t port);                            // 落盘
  boost::asio::awaitable<tl::expected<std::size_t, std::error_code>>
    update_server_met(const std::string& url);          // 拉取 + 按 (ip,port) 去重合并；
                                                          // 返回新增条目数

  // 搜索：关键词 + 类型/大小/源数过滤。需先 connect_server()——否则返回
  // errc::connect_failed。
  boost::asio::awaitable<tl::expected<std::vector<server::SearchResultItem>, std::error_code>>
    search(const std::string& keyword, const SearchFilters& filters);

  // 取回上一次 search() 的下一批结果（OP_QUERYMORERESULTS），必须与 search() 在同一连接上
  // 串行调用——该连接是单读者。未连接 -> errc::connect_failed。空 vector 表示服务器已无
  // 更多结果。
  boost::asio::awaitable<tl::expected<std::vector<server::SearchResultItem>, std::error_code>>
    search_more();

  // Kad(DHT) 状态。
  struct KadStatus { bool running = false; std::size_t contacts = 0; };
  KadStatus kad_status() const;

  // Kad(DHT) 关键词搜索。为避免与常驻 kad_run 协程争抢主 Kad socket 的单读者名额，每次调用
  // 都会构造一个短生命周期的临时 KadNetwork 实例（独立 socket，系统分配端口），查询用的
  // peer 取自主实例路由表的一份快照，查询结束后即丢弃。Kad 未启用或路由表为空 ->
  // errc::connect_failed（复用既有错误码，未新增）。搜索超时表现为 errc::timed_out，
  // 而不是空结果。必须在网络线程（rt.executor()）上调用。
  boost::asio::awaitable<tl::expected<std::vector<kad::KadSearchEntry>, std::error_code>>
    kad_search(const std::string& keyword);

  // 分享/上传。dirs 为空 -> 停止分享并释放入站监听器。
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    set_shared_dirs(std::vector<std::filesystem::path> dirs);
  std::vector<SharedFileInfo> shared_files() const;
  UploadStats upload_stats() const;

 private:
  struct Impl;
  std::shared_ptr<Impl> impl_;   // 协程持 weak_ptr；Session 析构后安全降级退出
};

}
```

### `TaskState` 状态机

```
queued --(调度器取出)--> connecting --(找到来源)--> downloading --(完成)--> completed
  ^                            |                          |
  |                            +----------(pause)---------+
  |                                       v
  +----------------(resume)----------- paused
  |
  +----------------(任意状态，遇不可恢复错误)--------------> failed
  |
  +----------------(cancel()，任意状态均可)-----------------> cancelled（从注册表移除；
                                                              不会作为 query() 观察到的
                                                              TaskSnapshot::state 出现）
```
`resume()` 接受 `paused` 或 `failed`；两者都重新进入 `queued`，并从任务的 `.part.met`
续传（已验证的分块不重新哈希）。`cancel()` 在任意状态下都可调用，会将任务从注册表中
移除；`remove_files=true` 会额外删除已下载的数据和 `.part.met`，且延迟到该任务在途的
协程完全退出后才执行（因此正处于网络 I/O 中的任务永远不会被抽走其正在写入的文件）。

### Phase 0 已知限制

以下是刻意划定的范围裁剪，在此显式记录而非隐藏假设——今天要嵌入 `Session` 的 GUI
应据此设计：

- **服务器推送状态不会实时刷新。** 成功 `connect_server` 之后，连接只在一个短窗口
  （≤ 2 秒）内同步读取，以捕获服务器的初始 `SERVERSTATUS`/`SERVERIDENT` 推送，随后
  连接转入空闲——不存在常驻读者。此后服务器端的推送（用户数/文件数变化等）不会被
  感知，也不会主动检测连接掉线；只有下一次前台请求（如 `search`）因连接已失效而
  失败时才会发现。
- **`enable_kad` 不会为下载增源。** 设为 `true` 只会让本地节点参与 Kad DHT（维护
  路由表、可被其它 Kad 节点发现、`shutdown()` 时把路由表落盘到 `nodes.dat`），但
  `add_download` 不会用 Kad 的 `find_sources` 结果扩充其来源列表——接入该功能会与
  Kad 常驻的单读者 socket 争抢同一连接，留待后续专项任务实现。`kad_status()` 会
  反映该子系统是否真正启动成功（若 `kad_udp_port` 已被其它进程占用，会静默禁用，
  不会导致 `Session` 构造失败）。
- **下载侧的 LowID 监听器与分享侧的入站上传监听器不能同时绑定同一个
  `cfg.tcp_port`。** 谁先占用谁生效；另一方会优雅降级（LowID 下载来源被跳过，
  或 `set_shared_dirs` 仍会完成扫描/发布但不会启动上传监听器，两种情况都只记一条
  `warn` 日志）而不是直接失败。占用方释放端口后，另一方重试即可恢复正常。
- **暂停粒度为 part 级**，而非 block 级：`pause()` 会先让该任务当前 part 上正在
  进行的块写入完成，任务才真正停止。

## 并发约定（重要）

- **只能由一个网络线程**访问 `BlockAllocator` / `PartFile` 状态 / `MultiSourceDownload`
  共享状态。不使用互斥锁，也不使用 `condition_variable`。
- **磁盘 I/O** 在 `disk_executor()` 上运行；`write_block_async` 通过
  `post(ex, bind_executor(ex, use_awaitable))` 完成网络 → 磁盘 → 网络的跳转
  （参见 README → Asio 注意事项）。
- 在 GoogleTest 协程中使用 `EXPECT_*` + `if (!x) co_return;`（不要使用 `ASSERT_*`——它会
  中止协程并导致 `io_context` 挂起）。
- **`ed2k::session::Session`** 在此基础上叠加了同样的规则：所有公共方法都必须在
  `rt.executor()` 上调用，其事件回调（`set_event_handler`）也在该线程上触发——完整的
  线程契约见上方 `ed2k/session` 一节。
