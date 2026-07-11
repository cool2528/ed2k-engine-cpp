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

Latest full Windows suite: **504/504 accounted for** (483 pass + 21 expected environment/live/CLI
skips). Live paths include server, Kad, download, upload, and cross-client resume validation.
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
```

**Live validation ✅**: server login/search/source lookup, Kad bootstrap/search, SX2 upload,
local-peer download, and bidirectional aMule `.part.met` handoff have been validated against
real infrastructure or a local aMule 2.3.3 peer. Public HighID peers often filter cloud IPs, so
a local aMule instance remains the reliable peer source for repeatable live tests.

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
