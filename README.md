# ed2k-engine-cpp

[简体中文](README.zh-CN.md)

A from-scratch C++20 implementation of the **eDonkey2000 / eMule (eD2k) protocol** engine —
link parsing, server and Kad sessions, upload/share, multi-source download with AICH corruption
recovery, and cross-client resume.
Built on Boost.Asio coroutines with a single-network-thread, lock-free design.

> **Protocol fidelity canon.** All wire formats are verified against the aMule source by
> byte-level comparison (opcodes, frame layouts, two-level AICH Merkle tree, REQUESTPARTS
> three-range encoding) — and confirmed against a real aMule 2.3.3 peer in live tests.
> No exceptions to byte fidelity.

## Status

| Area | State |
|---|---|
| Link / `server.met` / hash (ed2k + AICH + RED) | ✅ |
| Server session (login / search / get-sources, HighID + LowID callback) | ✅ |
| Single-source download + AICH two-level interop | ✅ |
| **Multi-source concurrent download (raccoon)** | ✅ |
| `.part.met` resume (met-first, no re-hash) | ✅ |
| Async disk I/O (offload to disk thread, network never blocks) | ✅ |
| `>4GiB` boundary (u64 blocks / offsets) | ✅ |
| Live real-peer validation | ✅ vs local aMule 2.3.3 + real eMule server (see [Live tests](#live-tests)) |
| Upload/share/credits + SourceExchange v2 | ✅ |
| Kad bootstrap/search/source lookup/publish | ✅ |
| TCP/UDP/server obfuscation | ✅ |
| Client infrastructure (IPFilter, preferences, stats, proxy, collection, scheduler, chat) | ✅ |
| Server UDP completeness / MuleInfo / compressed upload / aMule `.part.met` | ✅ |
| Linux / CI | ✅ |

Latest local acceptance (2026-07-15): Windows Debug **535/535** (519 pass + 16 live-gated
skips); Linux Debug **524/524** (508 pass + 16 live-gated skips); install and independent
consumer smokes green in all four Debug/Release configurations (2026-07-12). The managed
aMule 2.3.3 live harness passes both modes, including real upload evidence: aMule downloads
the complete fixture from the engine's upload session.
Version: `2.2.0`.

## Build

Requirements: **CMake ≥ 3.24**, **vcpkg** (`VCPKG_ROOT` set), C++20, a C++20 compiler.

**Windows** (Visual Studio 2022, `default` preset):

```bash
cmake --preset default            # configure (vcpkg manifest mode, x64 Debug)
cmake --build build/default       # build ed2k_core + ed2k-tool + ed2k_tests
ctest --preset default            # run tests (cwd build/default)
# Artifacts: build/default/Debug/ed2k-tool.exe, ed2k_tests.exe
```

**Linux** (GCC ≥ 13, Ninja, `linux` preset):

```bash
cmake --preset linux              # configure (vcpkg manifest, Ninja, Debug)
cmake --build --preset linux      # build
ctest --preset linux              # run tests (live skip without ED2K_LIVE)
# Artifacts: build/linux/ed2k-tool, ed2k_tests
```

### Install and use from another CMake project

Configure, build, and install ed2k to a prefix:

```bash
cmake --preset linux
cmake --build --preset linux
cmake --install build/linux --prefix "$PWD/build/stage"
```

An independent C++20 consumer can then use the installed package:

```cmake
cmake_minimum_required(VERSION 3.24)
project(app LANGUAGES CXX)

find_package(ed2k 2.2 CONFIG REQUIRED)

add_executable(app main.cpp)
target_compile_features(app PRIVATE cxx_std_20)
target_link_libraries(app PRIVATE ed2k::core)
```

Configure the consumer with the install prefix discoverable, for example:

```bash
cmake -S path/to/app -B path/to/app/build \
  -DCMAKE_PREFIX_PATH="$PWD/build/stage"
cmake --build path/to/app/build
```

The exported package does not bundle its dependencies. `tl-expected`, Zlib, OpenSSL,
Boost.Asio, and Threads must also be discoverable, typically through the same vcpkg toolchain or
through additional entries in `CMAKE_PREFIX_PATH`.

### Quick-start examples

**Hash a file** (no network, no Boost.Asio):

```cpp
#include <ed2k/hash.hpp>          // umbrella: core/hash + ed2k_hasher + aich_hasher
#include <ed2k/link/ed2k_link.hpp>
#include <iostream>

int main() {
  // Hash raw bytes
  const char data[] = "hello ed2k";
  auto hash = ed2k::hash_bytes({reinterpret_cast<const std::byte*>(data), 10});
  std::cout << "MD4: " << hash.to_hex() << "\n";

  // Parse an ed2k:// link
  auto link = ed2k::link::parse_link(
      "ed2k://|file|example.bin|1024|31D6CFE0D16AE931B73C59D7E0C089C0|/");
  if (link) {
    auto& f = std::get<ed2k::link::Ed2kFileLink>(*link);
    std::cout << "File: " << f.name << ", size: " << f.size << "\n";
  }
}
```

**Connect to a server and search** (requires Boost.Asio coroutines):

```cpp
#include <ed2k/net/runtime.hpp>
#include <ed2k/server/connection.hpp>
#include <ed2k/metfile/server_met.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <iostream>

boost::asio::awaitable<void> run(boost::asio::any_io_executor ex) {
  using namespace ed2k;
  server::ServerConnection srv(ex);
  auto id = co_await srv.connect_and_login(
      {.ip = IPv4::from_dotted("1.2.3.4").value(), .port = 4661},
      std::chrono::seconds(10));
  if (!id) co_return;

  auto results = co_await srv.search(
      server::SearchExpr::keyword("ubuntu"),
      std::chrono::seconds(15));
  if (results)
    for (auto& r : *results)
      std::cout << r.name << " (" << r.size << " bytes)\n";
}

int main() {
  net::IoRuntime rt;
  boost::asio::co_spawn(rt.io().get_executor(), run(rt.io().get_executor()),
                         boost::asio::detached);
  rt.io().run();
}
```

Push and pull-request CI covers Windows and Ubuntu in both Debug and Release. Every matrix entry
configures, builds, runs tests, installs, then configures, builds, and runs an independent
consumer against the installed package. Live tests remain opt-in and do not block this CI matrix.

## CLI — `ed2k-tool`

```
ed2k-tool [--config <preferences.dat>] [--ipfilter <ipfilter.dat>] [--proxy <uri>] [--obfuscation] <command> ...
ed2k-tool hash <file> [--aich] [--red]                 # compute ed2k link
ed2k-tool serverlist <server.met>                       # parse server.met
ed2k-tool get-serverlist <server.met>                   # fetch and merge server.met
ed2k-tool parse <ed2k-link>                             # parse an ed2k:// link
ed2k-tool login <server.met> [--ip:x.x.x.x] [--port:n]  # login to a server
ed2k-tool search <server.met> <keyword>                 # keyword search
ed2k-tool sources <server.met> <ed2k-link>              # get sources for a file
ed2k-tool publish <dir> [--server:server.met] [--ip:x.x.x.x] [--port:n]
ed2k-tool comment <ed2k-link> --rating:n --comment:text [--peer:ip:port]
ed2k-tool ipfilter <ipfilter.dat> [--block-check:ip] [--level:n]
ed2k-tool config <preferences.dat> [--set:key=value]
ed2k-tool stats <statistics.dat>
ed2k-tool collection create <collection> <ed2k-link>...
ed2k-tool collection list <collection>
ed2k-tool schedule add <rules.txt> <rule>
ed2k-tool schedule list <rules.txt>
ed2k-tool update-serverlist <url> <dest>
ed2k-tool kad-bootstrap <nodes.dat>                     # bootstrap Kad routing
ed2k-tool kad-search <nodes.dat> <keyword>              # Kad keyword search
ed2k-tool kad-find-sources <nodes.dat> <ed2k-link>      # Kad source lookup
ed2k-tool kad-publish <nodes.dat> <dir> [--port:n]      # publish share to Kad
ed2k-tool download <ed2k-link> [--out:PATH] [--server:server.met]
```

### Examples

```bash
# Hash a file into an ed2k link (with AICH root for corruption recovery)
ed2k-tool hash movie.avi --aich
# -> ed2k://|file|movie.avi|734003200|<md4>|h=<aich-base32>|/

# Login to a server (auto-rotates through server.met)
ed2k-tool login server.met
# -> client_id=0xXXXX high_id=1 flags=0x...

# Search + get sources + download
ed2k-tool search server.met "ubuntu"
ed2k-tool sources server.met "ed2k://|file|ubuntu.iso|...|/"
ed2k-tool download "ed2k://|file|ubuntu.iso|...|/" --out:ubuntu.iso --server:server.met

# Kad bootstrap/search/source lookup
ed2k-tool kad-bootstrap nodes.dat
ed2k-tool kad-search nodes.dat "ubuntu"
ed2k-tool kad-find-sources nodes.dat "ed2k://|file|ubuntu.iso|...|/"
```

`update-serverlist` accepts HTTP and HTTPS URLs. HTTPS always verifies the certificate chain and
requested hostname; there is no insecure verification bypass. The command follows at most five
redirects under one overall deadline. HTTP-to-HTTPS redirects are allowed; HTTPS-to-HTTP
downgrades are rejected. Successful 2xx responses, including `206`, require `Content-Length`;
chunked and connection-close-delimited bodies are unsupported. The destination is replaced
atomically only after the complete declared response body is written and file data is flushed.
Parent-directory crash durability is best-effort where directory fsync is unsupported.

`download` without `--server` falls back to an internal fallback server list. Downloaded files
are written via a sparse `PartFile` with per-part MD4 verification and `.part.met` resume —
re-running a partial download skips already-verified parts without re-hashing.

## Architecture

**Single `io_context`, single network thread.** All engine state (`BlockAllocator`, `PartFile`
state, `first_err`) is touched only on the network thread → **lock-free, no mutexes, no
`condition_variable`** (a cv would deadlock the single-threaded io_context).

- **raccoon multi-source** (`MultiSourceDownload`): N `peer_worker` coroutines via
  `co_spawn(detached)` share one `BlockAllocator`/`PartFile`. Each worker pulls blocks its peer
  has (`next_block_for_parts(has_part)` per-part bitmap filter). Completion is signalled by an
  `asio::experimental::channel<void(ec,int)>` — leading `ec` = op-status, errors via shared
  `first_err`. Source exhaustion → worker exits.
- **AICH two-level Merkle tree** (aMule-faithful): per-part leaves (53 blocks/part, last block
  aligned to part boundary), `AICHChecker` rebuilds the tree from proof hashes to bind a trusted
  master. `peer_worker` negotiates the master via `OP_AICHFILEHASHREQ/ANS`; mismatch → graceful
  degradation to MD4-only.
- **Async disk I/O**: `PartFile::write_block_async` runs `f_.seekp/write` and part-MD4 readback
  on a separate disk executor (`IoRuntime::disk_executor()` = `thread_pool{1}`, single thread
  serializes `f_` → no strand). Network thread changes state only. State/I/O separation enforced
  by a two-post hop with `bind_executor` (see [Asio gotcha](#asio-gotcha)).
- **`.part.met` resume**: `PartFile` ctor is met-first — a valid `.part.met` (magic + hash +
  part_hashes match) restores `part_done_`/`block_done_` from gaps **without re-hashing**;
  missing/corrupt/stale → falls back to `rehash_all`. Part completion persists `.part.met`.

### Asio gotcha

`co_await asio::post(ex, use_awaitable)` resumes the coroutine on its **associated** executor
(the network thread), **not** `ex` — so the disk write would still run on the network thread
(no offload). Must use `asio::post(ex, asio::bind_executor(ex, asio::use_awaitable))` to force
resumption on `ex`. `DiskExecutorRunsOnSeparateThread` test locks this in.

### Key parameters

| Parameter | Value |
|---|---|
| `PART_SIZE` | 9,728,000 bytes |
| `AICH_BLOCK_SIZE` | 184,320 bytes (full part = 53 blocks, last = 143,360) |
| `peer::Block.start/end` | `u64` (>4GiB safe) |
| REQUESTPARTS ranges | 3 × `[start,end)` per request |

## Live tests

Live tests are gated behind `ED2K_LIVE` and skip by default (mock loopback runs without them):

```bash
# Server session (Login / Search / GetSources) — real eMule server
ED2K_LIVE=1 ED2K_SERVER=ip:port ED2K_LINK="ed2k://|file|...|/" \
  ED2K_EXPECT_MD4=<hex> ctest --preset default -R Live

# Peer download (LocalPeerCompletes) — direct connect to an eMule/aMule HighID peer
ED2K_LIVE=1 ED2K_LINK="ed2k://|file|...|/" ED2K_SOURCE=ip:port \
  ED2K_EXPECT_MD4=<hex> ./build/default/Debug/ed2k_tests.exe \
    --gtest_filter=LiveDownload.LocalPeerCompletes

# Managed local aMule 2.3.3 obfuscation harness
./scripts/live/setup-amule-obfuscation.ps1
./scripts/live/run-amule-obfuscation.ps1 -Mode required -TestExe build/default/Debug/ed2k_tests.exe
./scripts/live/run-amule-obfuscation.ps1 -Mode optional -TestExe build/linux/ed2k_tests
```

**Live validation ✅**: server login/search/source lookup, Kad bootstrap/search, SX2 upload,
local-peer download, and bidirectional aMule `.part.met` handoff have been validated against
real infrastructure or a local aMule 2.3.3 peer. Public HighID peers often filter cloud IPs, so
a local aMule instance remains the reliable peer source for repeatable live tests.

The managed harness now enforces `daemon ready -> upload listener ready -> amulecmd Add source
link`. The 2026-07-12 required mode passed all 5 focused tests. Optional obfuscation itself passed
4/4, but the upload evidence remains an explicit failed gate: aMule 2.3.3 accepted the EC `Add`
command yet retained `Total sources: 0` and never opened the upload connection. The logs are kept
under `.tmp_live_amule_obfuscation/optional/logs/`; this result is not reported as a green upload
interop run.

## Project layout

```
apps/cli/         ed2k-tool CLI
include/ed2k/     public headers (net, peer, server, download, hash, codec, link, metfile)
src/              library sources (mirror include/ layout)
tests/            GoogleTest (single ed2k_tests executable; live_* gated by ED2K_LIVE)
docs/             RELEASE-PLAN.md (canonical progress tracker), specs/, plans/
```

## Acknowledgements

The [aMule](https://github.com/amule-project/amule) source is the authoritative wire-format
reference; every opcode, frame layout, and hash variant here was byte-compared against it.

## License

Released under the [MIT License](LICENSE).
