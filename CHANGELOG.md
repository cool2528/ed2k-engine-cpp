# Changelog

All notable changes to ed2kengine. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Source-of-truth progress tracker: `docs/RELEASE-PLAN.md`.

## Unreleased

### Changed
- The managed aMule upload harness now orders startup as daemon readiness, upload-listener
  readiness, then `amulecmd Add` source-link injection. Windows port preflight uses a local bind
  probe instead of the potentially blocking `Get-NetTCPConnection` cmdlet.
- The install tree now exposes a versioned CMake package with the `ed2k::core` target and
  dependency discovery for independent C++20 consumers; the push/pull-request Windows/Ubuntu
  Debug/Release CI matrix configures, builds, tests, installs, and configures/builds/runs that
  consumer. Live tests remain opt-in and non-blocking.
- `update-serverlist` now accepts HTTP and HTTPS, strictly verifies certificate chains and
  hostnames without an insecure bypass, follows at most five redirects under one overall
  deadline, rejects HTTPS-to-HTTP downgrade redirects, and atomically replaces the destination
  only after the complete `Content-Length`-declared 2xx response body is written and file data is
  flushed. Parent-directory crash durability is best-effort where directory fsync is unsupported.

### Tests
- 2026-07-12 local cross-platform acceptance: Windows Debug/Release each 534 total, 519 pass +
  15 live skip, 0 fail; Linux Debug/Release each 523 total, 508 pass + 15 live skip, 0 fail.
  Install and independent consumer smokes passed in all four configurations.
- Managed aMule 2.3.3 required obfuscation passed 5/5. Optional obfuscation passed 4/4, while its
  real upload evidence remains failed: the EC `Add` command was accepted but aMule retained zero
  sources and never connected. The bounded public-server probe also found no reachable endpoint
  in five attempts; neither failure is represented as successful live evidence.

## [2.2.0] — 2026-07-06

### Added — aMule protocol-level feature parity
- Upload/share pipeline: known-file index, server publish, upload session/queue, rate limiting,
  client credits, SourceExchange v2, comments, and ratings.
- Kad support: routing table, bootstrap, Kad2 UDP, keyword/source/notes search and publish,
  firewalled/buddy/callback flows, and CLI Kad commands.
- Protocol obfuscation: built-in MD5/RC4, TCP encrypted stream handshake, UDP/server obfuscation,
  negotiation bits, and fallback paths.
- Client infrastructure: IPFilter, preferences, statistics, categories, friend/client lists,
  proxy support, HTTP server-list updates, collections, preview, scheduler, and chat relay.
- eD2k completeness: server UDP v2 source query/ident, server-list exchange, MuleInfo handshake,
  AICH sharing, compressed upload blocks, aMule-faithful `.part.met`, and large-file boundaries.

### Changed — code quality modernization
- Public async/network/download handles moved behind PIMPL-style implementations while preserving
  coroutine APIs.
- Server and UDP observer registration now returns RAII subscriptions.
- Core hash/codec/IP APIs gained targeted `[[nodiscard]]`, `constexpr`, and safe `noexcept`
  contracts; byte-range APIs use a `std::byte` contiguous range concept.
- `std::hash<MD4Hash>` was strengthened and selected formatting paths moved to C++20 `std::format`.
- C++23 migration remains deferred; the release stays on C++20.

### Tests
- Windows and WSL full suites: 453 total, 444 pass + 9 live-gated skip, 0 fail.
- Live validation includes real server paths, Kad bootstrap/search, SX2 upload, local aMule peer
  download, and bidirectional aMule `.part.met` handoff.

## [1.0.0] — 2026-07-04

### Fixed — live protocol fidelity vs aMule 2.3.3 (R0-1)
Discovered by byte-comparison against aMule source while validating
`LiveDownload.LocalPeerCompletes` against a local aMule peer (single-part 5.57MB +
multi-part 29MB, both MD4-verified):
- **`request_blocks` multi-subframe accumulation**: aMule `CreateStandardPackets` splits each
  requested range into ~10240B sub-frames (not one frame per range). Replaced the
  `while(blocks.size()<3)` loop with `accumulate_blocks` (per-range buffer, byte-offset stitching
  until each active range is continuously covered).
- **Single-part files skip `request_hashset`**: aMule silently drops the answer when
  `GetHashCount()==0`; `size <= PART_SIZE` now skips the request and `PartFile` synthesizes
  `{file_hash}`.
- **HELLO/HELLOANSWER asymmetry**: HELLO carries a leading `0x10` hashsize byte, HELLOANSWER
  does not. Split `encode_hello_packet` (adds 0x10) / `decode_hello` (validates & skips it).
- **HELLO body trailing server_ip/server_port**: `SendHelloTypePacket` always appends
  `server_ip:4 BE` + `server_port:2` (0/0 when not server-connected); was missing.
- **HASHSETANSWER leading file_hash**: `[file_hash:16][count:2][part_hashes]`; `ProcessHashsetAnswer`
  validates the prefix against the requested hash. `decode_hashset_answer` now takes `expected`.
- **ed2k file hash Red variant default**: aMule appends an empty trailing part `MD4("")` for files
  that are an exact multiple of PART_SIZE; `hash_bytes`/`hash_file` default switched Blue → Red.
- **FILESTATUS count=0 = complete file**: aMule sends `[hash:16][count=0]` (no bitset) for complete
  shared files (`!IsPartFile() → WriteUInt16(0)`), meaning all parts available — not "0 parts".
  Empty `fs->parts` now maps to "all parts servable" at both download sites.
- `PartFile::num_parts` now derives from `ceil(size/PART_SIZE)` (the Red empty trailing part holds
  no data and must not occupy a `part_done_`/`block_done_` slot); bounds-guarded hash lookups.
- Removed per-batch `OP_OUTOFPARTREQS` from 6 mock peers (aMule sends it only on upload-slot
  reclamation, not per batch). Added 4 unit tests (HELLO packet/decode, hashset hash-mismatch).

### Added — multi-source download & resume (P4c-3)
- **raccoon multi-source concurrent download**: `MultiSourceDownload` spawns N `peer_worker`
  coroutines sharing one `BlockAllocator`/`PartFile`; per-part bitmap block dispatch
  (`next_block_for_parts`); completion via `asio::experimental::channel` (no
  `condition_variable` — would deadlock the single-threaded `io_context`).
- **`peer::Block` u32 → u64**: removes the ~4GiB single-block limit; `decode_*_i64` no longer
  silently narrows >4GiB offsets.
- **`.part.met` resume**: `PartFile` ctor is met-first — valid `.part.met` restores part state
  from gaps without re-hashing; missing/corrupt/stale falls back to `rehash_all`. Part completion
  persists `.part.met`. (Internal round-trip format; aMule-faithful cross-client resume deferred.)
- **Async disk I/O**: `PartFile::write_block_async` offloads `f_.seekp/write` + part-MD4 readback
  to a separate disk thread (`IoRuntime::disk_executor()`); network thread changes state only.
  `set_disk_executor` injects the disk pool (default = network thread, sync-equivalent).
- **>4GiB boundary test** (`Beyond4GiBBoundaryRoundTrip`): verifies u64 offsets survive
  `BlockAllocator → encode_request_parts_i64 → PartFile.seekp/write/readback/MD4` end-to-end.

### Added — AICH two-level interop (P4c-2)
- Two-level Merkle tree (`aich_hash_bytes`) matching aMule `SHAHashSet` split rules.
- `AICHChecker` rebuilds the tree from proof hashes to bind a trusted master (two-step verify).
- Wire protocol corrected against aMule source: `AICHREQUEST/ANSWER`=0x9B/0x9C,
  `AICHFILEHASHREQ/ANS`=0x9E/0x9D, protocol layer `eMule`(0xC5); V2 recovery data decode.
- `peer_worker` master-hash negotiation (`OP_AICHFILEHASHREQ/ANS`); mismatch → graceful
  degradation to MD4-only.
- per-part block model (blocks never cross part boundary) — required for AICH leaf alignment.

### Added — server session & LowID callback (P4c-1)
- `ed2k-tool login` / `search` / `sources` / `download`.
- LowID callback framework: `InboundListener` + `OP_CALLBACKREQUEST` + `peer_worker` branch.

### Performance
- `c2c` socket `TCP_NODELAY` (AICH short frames avoid Nagle + delayed-ACK stalls):
  single-source 57s → 2.9s, corruption recovery 91s → 6.3s.

### Tests
- 229 pass, 5 skip (live-gated only). `LiveDownload.LocalPeerCompletes` green vs local aMule 2.3.3
  peer (single-part + multi-part 29MB, MD4 verified). Previously-skipped `RequestPartsI64RoundTrip`
  placeholder replaced by the real `Beyond4GiBBoundaryRoundTrip`.

## [0.1.0] — initial

- ed2k link parse, `server.met` parse, ed2k/AICH/RED hashing.
- Single-source download with per-part MD4 verification.
- `ed2k-tool hash` / `serverlist` / `parse`.
