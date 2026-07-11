# API overview

[简体中文](API.zh-CN.md)

Public surface lives under `include/ed2k/`. All network APIs are Boost.Asio coroutines
(`co_await`-able, `awaitable<T>`); the engine runs on a single `io_context` / single network
thread (see README → Architecture). Error handling uses `tl::expected<T, std::error_code>`.

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

## Concurrency contract (important)

- **Only one network thread** may touch `BlockAllocator` / `PartFile` state / `MultiSourceDownload`
  shared state. No mutexes, no `condition_variable`.
- **Disk I/O** runs on `disk_executor()`; `write_block_async` hops network → disk → network via
  `post(ex, bind_executor(ex, use_awaitable))` (see README → Asio gotcha).
- In GoogleTest coroutines use `EXPECT_*` + `if (!x) co_return;` (no `ASSERT_*` — it aborts the
  coroutine and hangs the `io_context`).
