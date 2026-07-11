# API 概览

[English](API.md)

公共 API 位于 `include/ed2k/` 下。所有网络 API 都是 Boost.Asio 协程
（可使用 `co_await`，返回 `awaitable<T>`）；引擎运行在单个 `io_context` / 单个网络
线程上（参见 README → 架构）。错误处理使用 `tl::expected<T, std::error_code>`。

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
    Builder& disk_executor(boost::asio::any_io_executor);
    MultiSourceDownload build();
  };
  void set_disk_executor(boost::asio::any_io_executor);  // 注入磁盘池（默认值 = 网络执行器）
  awaitable<expected<void, ec>> run(milliseconds total_timeout, std::size_t n_workers);
};
```

注入 `KadNetwork` 后，`MultiSourceDownload::run` 会向本地路由表查询距离文件哈希最近的
联系人，并在现有多来源设置循环之前追加直接 Kad 来源结果。服务器来源仍具有最高优先级；
Kad 仅用于扩充候选列表。

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
追加 Kad 直接来源 → `MultiSourceDownload(...).run(total_timeout, 3)`。

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

## 并发约定（重要）

- **只能由一个网络线程**访问 `BlockAllocator` / `PartFile` 状态 / `MultiSourceDownload`
  共享状态。不使用互斥锁，也不使用 `condition_variable`。
- **磁盘 I/O** 在 `disk_executor()` 上运行；`write_block_async` 通过
  `post(ex, bind_executor(ex, use_awaitable))` 完成网络 → 磁盘 → 网络的跳转
  （参见 README → Asio 注意事项）。
- 在 GoogleTest 协程中使用 `EXPECT_*` + `if (!x) co_return;`（不要使用 `ASSERT_*`——它会
  中止协程并导致 `io_context` 挂起）。
