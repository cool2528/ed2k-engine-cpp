# API overview

[简体中文](API.zh-CN.md)

Public surface lives under `include/ed2k/`. All network APIs are Boost.Asio coroutines
(`co_await`-able, `awaitable<T>`); the engine runs on a single `io_context` / single network
thread (see README → Architecture). Error handling uses `tl::expected<T, std::error_code>`.

## Consuming the installed CMake package

Consumers require C++20 and link the exported `ed2k::core` target:

```cmake
cmake_minimum_required(VERSION 3.24)
project(app LANGUAGES CXX)

find_package(ed2k 2.2 CONFIG REQUIRED)

add_executable(app main.cpp)
target_compile_features(app PRIVATE cxx_std_20)
target_link_libraries(app PRIVATE ed2k::core)
```

After installing ed2k with `cmake --install <build-dir> --prefix <install-prefix>`, configure the
consumer with `<install-prefix>` in `CMAKE_PREFIX_PATH`. The exported package does not bundle its
dependencies: `spdlog`, `tl-expected`, Zlib, OpenSSL, Boost.Asio, and Threads must also be
discoverable through a vcpkg/toolchain setup or dependency prefixes.

Push and pull-request CI runs on Windows and Ubuntu, in Debug and Release. Each job performs
configure, build, tests, install, and independent consumer configure/build/run. Live tests remain
opt-in and do not block this CI matrix.

The 2026-07-12 local package acceptance repeated those four build/test/install/consumer paths:
Windows Debug/Release were 519 pass + 15 live skip out of 534, and Linux Debug/Release were
508 pass + 15 live skip out of 523, with all consumer executables returning success.

## `ed2k/net` — runtime & transport

```cpp
namespace ed2k::net {
class IoRuntime {
 public:
  boost::asio::any_io_executor executor();          // network thread executor (io_context)
  boost::asio::any_io_executor disk_executor();     // disk I/O thread pool (thread_pool{1})
  void run(); void restart(); void stop();
  boost::asio::io_context& context();
  template<class F> void co_spawn_detached(F&&);    // run a coroutine on the network thread
};
}
```
- `executor()` — for all network work (server/peer sockets, coroutines).
- `disk_executor()` — inject into `MultiSourceDownload::set_disk_executor` to offload writes.
- `connection.hpp` / `framing.hpp` / `packet.hpp` — TCP frame encode/decode (eDonkey + eMule
  protocol bytes), `Packet{protocol, opcode, payload}`.

## `ed2k/hash` — hashing

```cpp
enum class HashVariant { Blue, Red };
struct HashResult { FileHash file_hash; std::vector<PartHash> part_hashes; };
HashResult hash_bytes(std::span<const std::byte>, HashVariant = HashVariant::Red);
tl::expected<HashResult, std::error_code> hash_file(const std::filesystem::path&, HashVariant = HashVariant::Red);
tl::expected<AICHHash, std::error_code> aich_hash_file(const std::filesystem::path&);  // two-level Merkle root
```
- `aich_hash_bytes` (in `aich_hasher.hpp`) builds the two-level per-part Merkle tree matching
  aMule `SHAHashSet` (constants `PART_SIZE`=9,728,000, `AICH_BLOCK_SIZE`=184,320).

## `ed2k/core/hash.hpp` — hash types

```cpp
using FileHash = MD4Hash; using UserHash = MD4Hash; using PartHash = MD4Hash;   // 16-byte
class MD4Hash  { static tl::expected<MD4Hash,std::error_code> from_hex(std::string_view); std::string to_hex() const; };
class AICHHash { /* 20-byte */ std::string to_base32() const; };
struct IPv4 { static std::optional<IPv4> from_dotted(std::string_view); std::string to_dotted() const; };
```

## `ed2k/link/ed2k_link.hpp` — link parsing

```cpp
struct Ed2kFileLink { std::string name; std::uint64_t size; FileHash hash; std::optional<AICHHash> aich; std::vector<SourceEndpoint> sources; };
struct ServerLink    { IPv4 ip; std::uint16_t port; };
struct ServerListLink{ std::string url; };
using Ed2kLink = std::variant<Ed2kFileLink, ServerLink, ServerListLink>;
tl::expected<Ed2kLink, std::error_code> parse_link(std::string_view);
std::string to_string(const Ed2kFileLink&);
```

## `ed2k/metfile` — metadata files

```cpp
// server.met
tl::expected<ServerMet, std::error_code> parse_server_met(std::span<const std::byte>);
// .part.met (aMule 0xE0/0xE2 format; legacy internal gap blobs still parse)
struct PartFileState { FileHash hash; std::vector<PartHash> part_hashes; std::vector<std::pair<std::uint64_t,std::uint64_t>> gaps; };
tl::expected<PartFileState, std::error_code> parse_part_met(std::span<const std::byte>);
std::vector<std::byte> write_part_met(const PartFileState&);
```

## `ed2k/server` — server session

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

## `ed2k/download` — download engine

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

class BlockAllocator {  // per-part block model; blocks never cross a part boundary
 public:
  BlockAllocator(std::uint64_t size, const std::vector<PartHash>&, std::optional<AICHHash> root);
  std::optional<std::tuple<std::size_t part, std::size_t bip, std::uint64_t start, std::uint64_t end>> next_block();
  std::optional<...> next_block_for_parts(const std::vector<bool>& has_part);  // raccoon: peer-has filter
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
    Builder& kad_network(kad::KadNetwork&);              // optional Kad source augmentation
    Builder& disk_executor(boost::asio::any_io_executor);
    MultiSourceDownload build();
  };
  void set_disk_executor(boost::asio::any_io_executor);  // inject disk pool (default = network ex)
  awaitable<expected<void, ec>> run(milliseconds total_timeout, std::size_t n_workers);
};
```

When a `KadNetwork` is injected, `MultiSourceDownload::run` asks the local routing table for the
closest contacts to the file hash and appends direct Kad source results before the existing
multi-source setup loop. Server sources remain first in priority; Kad only augments the candidate list.

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

## `ed2k/app/server_session.hpp` — high-level orchestration

```cpp
namespace ed2k::app {
struct ServerTarget { IPv4 ip; std::uint16_t port; };
struct DownloadOpts {
  std::filesystem::path out_path;
  std::chrono::milliseconds per_server_timeout = std::chrono::seconds(30);
  std::chrono::milliseconds total_timeout = std::chrono::seconds(120);
  std::uint16_t client_port = 4662;   // InboundListener port (LowID callback)
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
`download_link` does: login → `get_sources` → construct `InboundListener` only if LowID sources
exist (else HighID-only direct connect) → optionally append Kad direct sources when
`DownloadOpts::kad_network` is set → `MultiSourceDownload(...).run(total_timeout, 3)`.

## `ed2k/infra/http_download.hpp` — verified HTTP(S) download

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

`fetch` accepts HTTP and HTTPS, verifies HTTPS certificate chains and hostnames, and exposes no
insecure verification bypass. It follows at most five redirects using one overall deadline for
all network and TLS operations. HTTP-to-HTTPS redirects are allowed; HTTPS-to-HTTP downgrades are
rejected.

Any 2xx status, including `206 Partial Content`, is accepted only when it includes a valid
`Content-Length`. Chunked and connection-close-delimited bodies are unsupported. The complete
declared response body is written to a temporary file and flushed before atomic installation at
`destination`; parent-directory crash durability is best-effort on platforms where directory
fsync is unsupported. Failures do not publish a partial body.

## `ed2k/share` — sharing, upload, credits

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

`UploadSession` is the upload-side C2C role: it answers filename/status/hashset/block/AICH
requests, applies queue/throttle/credit hooks when provided, answers shared-file and SX2 requests,
and stores incoming `OP_FILEDESC` rating/comment on the current requested file.

`peer::C2CConnection` also exposes upload/share helpers:

```cpp
awaitable<expected<peer::SourceExchangeAnswer, ec>>
  request_sources2(FileHash, milliseconds timeout);
awaitable<expected<void, ec>>
  send_file_desc(std::uint8_t rating, std::string_view comment);
```

## `ed2k/session` — Session facade (GUI embedding)

`Session` is the GUI-friendly facade over the lower-level building blocks above: a task
registry, download orchestration, concurrency scheduling, 1s speed sampling, server/Kad/share
management, and a single event stream — everything a desktop client needs without touching
`MultiSourceDownload`, `ServerConnection`, or `KadNetwork` directly.

> **Threading contract — read before using `Session` (both rules are load-bearing, not advisory):**
> 1. **Every public `Session` method must be called on the network thread**, i.e. from a
>    coroutine or callback running on `IoRuntime::executor()`. `Session` keeps no internal
>    `mutex`/`condition_variable`; calling from any other thread is a data race, not merely
>    unsupported.
> 2. **The event callback registered via `set_event_handler` fires on the network thread too.**
>    A GUI integration must not touch UI widgets directly from inside it. Post/queue the event to
>    the UI thread (e.g. Qt `QMetaObject::invokeMethod(..., Qt::QueuedConnection)`) before acting
>    on it. The callback **must not throw** (it runs inside a detached coroutine — an escaping
>    exception calls `std::terminate`) and **must not re-enter `Session`** (e.g. call
>    `add_download`/`cancel` from inside the callback); queue to the UI thread and act there.
> 3. **Foreground requests on the server connection must be serialized.** `connect_server`,
>    `search`, and `update_server_met` all read the single shared server socket. Await one to
>    completion before issuing the next — never fire a `search` while a `connect_server` is still
>    in flight — or two coroutines will `recv` the same socket concurrently (the single-reader
>    model breaks). Download tasks each use their own independent connection and are exempt.

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
  std::filesystem::path data_dir;                          // server.met etc.
  std::size_t max_concurrent_tasks = 3;
  peer::ObfuscationPolicy obfuscation = peer::ObfuscationPolicy::disabled;
  std::optional<UserHash> user_hash;
  std::optional<app::ServerTarget> server_override;         // preferred server (test/settings)
  std::chrono::milliseconds per_server_timeout = std::chrono::seconds(30);
  std::chrono::milliseconds task_io_timeout = std::chrono::seconds(60);
  bool enable_kad = false;                                  // see Phase 0 limitations below
  std::uint16_t kad_udp_port = 4672;                        // 0 = OS-assigned
};

struct TaskStateEvent { std::uint64_t task_id; TaskState state; std::error_code error; };
struct ServerInfo { IPv4 ip; std::uint16_t port; std::string name; bool connected; };
struct ServerStateEvent {
  bool connected; IPv4 ip; std::uint16_t port; std::string name;
  bool high_id; std::uint32_t users, files;
};
using SessionEvent = std::variant<TaskStateEvent, ServerStateEvent>;

struct SearchFilters {
  server::FileType type = server::FileType::Any;
  std::uint64_t min_size = 0;    // bytes; 0 = unbounded
  std::uint32_t min_avail = 0;   // minimum source count; 0 = unbounded
};

struct SharedFileInfo {
  std::string name; std::filesystem::path path; std::uint64_t size; FileHash hash;
  std::uint64_t uploaded;  // approximate: session-wide upload total when sharing one file, else an
                           // un-split aggregate across all shared files (see class docs below)
};

struct UploadStats { std::size_t active_sessions; std::uint64_t total_uploaded; };

class ED2K_EXPORT Session {
 public:
  Session(net::IoRuntime& rt, SessionConfig cfg);
  ~Session();
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  // Task lifecycle — every method below must run on rt.executor().
  std::uint64_t add_download(const Ed2kFileLink& link, const std::filesystem::path& save_dir);
  bool pause(std::uint64_t id);                        // queued/connecting/downloading -> paused
  bool resume(std::uint64_t id);                       // paused/failed -> queued (re-enters the
                                                         // scheduler; resumes from .part.met)
  bool cancel(std::uint64_t id, bool remove_files);    // any state -> removed; remove_files also
                                                         // deletes data + .part.met, deferred until
                                                         // the task's in-flight coroutine exits
  std::optional<TaskSnapshot> query(std::uint64_t id) const;
  std::vector<TaskSnapshot> query_all() const;
  void set_event_handler(std::function<void(const SessionEvent&)> handler);
  void shutdown() noexcept;   // stops every task; idempotent; also called from the destructor

  // Server management: connection state + list maintenance + server.met persistence.
  // target == nullopt rotates through cfg.server_override + server.met + a built-in fallback list.
  boost::asio::awaitable<tl::expected<server::LoginResult, std::error_code>>
    connect_server(std::optional<app::ServerTarget> target);
  void disconnect_server();                            // idempotent; no-op if not connected
  bool server_connected() const;
  std::vector<ServerInfo> server_list() const;
  bool add_server(IPv4 ip, std::uint16_t port, const std::string& name);      // de-duped; persists
  bool remove_server(IPv4 ip, std::uint16_t port);                            // persists
  boost::asio::awaitable<tl::expected<std::size_t, std::error_code>>
    update_server_met(const std::string& url);          // fetch + merge by (ip,port); returns
                                                          // count of newly added entries

  // Search: keyword + type/size/source-count filters. Requires connect_server() first —
  // otherwise returns errc::connect_failed.
  boost::asio::awaitable<tl::expected<std::vector<server::SearchResultItem>, std::error_code>>
    search(const std::string& keyword, const SearchFilters& filters);

  // Kad(DHT) status.
  struct KadStatus { bool running = false; std::size_t contacts = 0; };
  KadStatus kad_status() const;

  // Sharing / upload. dirs empty -> stops sharing and releases the inbound listener.
  boost::asio::awaitable<tl::expected<void, std::error_code>>
    set_shared_dirs(std::vector<std::filesystem::path> dirs);
  std::vector<SharedFileInfo> shared_files() const;
  UploadStats upload_stats() const;

 private:
  struct Impl;
  std::shared_ptr<Impl> impl_;   // coroutines hold a weak_ptr; safe degrade after Session dtor
};

}
```

### `TaskState` state machine

```
queued --(scheduler picks up)--> connecting --(source found)--> downloading --(complete)--> completed
  ^                                    |                              |
  |                                    +------------(pause)-----------+
  |                                                 v
  +-----------------------(resume)------------- paused
  |
  +-------------------------(any state, on unrecoverable error)------> failed
  |
  +-------------------------(cancel(), from any state)----------------> cancelled (removed from
                                                                          the registry; not a
                                                                          TaskSnapshot::state you
                                                                          will observe via query())
```
`resume()` accepts `paused` or `failed`; both re-enter `queued` and resume from the task's
`.part.met` (no re-hash of already-verified parts). `cancel()` is accepted from any state and
removes the task from the registry; `remove_files=true` additionally deletes the downloaded data
and `.part.met`, deferred until the task's in-flight coroutine has fully exited (so a task mid
network I/O never has its backing file yanked out from under it).

### Phase 0 known limitations

These are deliberate scope cuts recorded here rather than hidden assumptions — a GUI embedding
`Session` today should design around them:

- **Server push status is not live-refreshed.** After a successful `connect_server`, the
  connection reads a short window (≤ 2s) to capture the server's initial `SERVERSTATUS` /
  `SERVERIDENT` push, then goes idle — there is no persistent reader. Later server-side pushes
  (user/file count changes, etc.) are not observed, and a dropped connection is not detected
  proactively; it only surfaces the next time a foreground request (e.g. `search`) fails against
  the now-dead connection.
- **`enable_kad` does not feed download source discovery.** Setting it to `true` makes the local
  node participate in the Kad DHT (routing table maintained, discoverable by other Kad nodes,
  `nodes.dat` persisted on `shutdown()`), but `add_download` does not augment its source list from
  Kad `find_sources` results — wiring that in would contend with Kad's single-reader socket for
  the same connection and is left for a future dedicated task. `kad_status()` reports whether the
  subsystem actually started (it silently disables itself, without failing `Session` construction,
  if `kad_udp_port` is already taken by another process).
- **The download-side LowID listener and the share inbound-upload listener cannot both bind
  `cfg.tcp_port` at the same time.** Whichever claims it first wins; the other degrades
  gracefully (a LowID download source is skipped, or `set_shared_dirs` completes its scan/publish
  but does not start the upload listener, logging a `warn` either way) rather than failing
  outright. Retrying the losing side after the winner releases the port succeeds normally.
- **Pause granularity is per-part**, not per-block: `pause()` lets in-flight block writes for the
  task's current part finish before the task actually stops.

## Concurrency contract (important)

- **Only one network thread** may touch `BlockAllocator` / `PartFile` state / `MultiSourceDownload`
  shared state. No mutexes, no `condition_variable`.
- **Disk I/O** runs on `disk_executor()`; `write_block_async` hops network → disk → network via
  `post(ex, bind_executor(ex, use_awaitable))` (see README → Asio gotcha).
- In GoogleTest coroutines use `EXPECT_*` + `if (!x) co_return;` (no `ASSERT_*` — it aborts the
  coroutine and hangs the `io_context`).
- **`ed2k::session::Session`** layers the same rule on top: every public method must be called on
  `rt.executor()`, and its event callback (`set_event_handler`) also fires on that thread — see
  the `ed2k/session` section above for the full threading contract.
