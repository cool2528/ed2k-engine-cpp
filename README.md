# ed2kengine

A from-scratch C++20 implementation of the **eDonkey2000 / eMule (eD2k) protocol** engine —
link parsing, server session, multi-source download with AICH corruption recovery, and resume.
Built on Boost.Asio coroutines with a single-network-thread, lock-free design.

> **Protocol fidelity canon.** All wire formats are verified against the aMule source by
> byte-level comparison (opcodes, frame layouts, two-level AICH Merkle tree, REQUESTPARTS
> three-range encoding). No exceptions to byte fidelity.

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
| Live real-server validation | ⏳ requires real eMule server (see [Live tests](#live-tests)) |
| Linux / CI | ⏳ planned (R0-2/R0-3) |

Mock loopback tests: **225 pass, 4 skip** (live-gated only). Version: `0.1.0` (→ `1.0.0` at release).

## Build

Requirements: **Visual Studio 2022**, **CMake ≥ 3.24**, **vcpkg** (`VCPKG_ROOT` set), C++20.

```bash
cmake --preset default            # configure (vcpkg manifest mode, x64 Debug)
cmake --build build/default       # build ed2k_core + ed2k-tool + ed2k_tests
ctest --preset default            # run tests (cwd build/default)
```

Artifacts: `build/default/Debug/ed2k-tool.exe` (CLI), `ed2k_tests.exe` (tests).

## CLI — `ed2k-tool`

```
ed2k-tool hash <file> [--aich] [--red]                 # compute ed2k link (P1)
ed2k-tool serverlist <server.met>                       # parse server.met
ed2k-tool parse <ed2k-link>                             # parse an ed2k:// link
ed2k-tool login <server.met> [--ip:x.x.x.x] [--port:n]  # login to a server (P4c-1)
ed2k-tool search <server.met> <keyword>                 # keyword search
ed2k-tool sources <server.met> <ed2k-link>              # get sources for a file
ed2k-tool download <ed2k-link> [--out:PATH] [--server:server.met]  # download
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
```

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

Four tests are gated behind `ED2K_LIVE` and skip by default:

```bash
ED2K_LIVE=1 ED2K_SERVER=ip:port ED2K_LINK="ed2k://|file|...|/" \
  ED2K_EXPECT_MD4=<hex> ctest --preset default -R Live
```

These require a real eMule server and a known-good file link. Mock loopback is green; live
green is the remaining v1.0 validation gate (R0-1).

## Project layout

```
apps/cli/         ed2k-tool CLI
include/ed2k/     public headers (net, peer, server, download, hash, codec, link, metfile)
src/              library sources (mirror include/ layout)
tests/            GoogleTest (single ed2k_tests executable; live_* gated by ED2K_LIVE)
docs/             RELEASE-PLAN.md (canonical progress tracker), specs/, plans/
```

## License

See source headers. (Project-internal; confirm before redistribution.)
