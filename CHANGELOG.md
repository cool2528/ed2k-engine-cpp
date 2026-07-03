# Changelog

All notable changes to ed2kengine. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Source-of-truth progress tracker: `docs/RELEASE-PLAN.md`.

## [Unreleased] — toward 1.0.0

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
- 225 pass, 4 skip (live-gated only). Previously-skipped `RequestPartsI64RoundTrip` placeholder
  replaced by the real `Beyond4GiBBoundaryRoundTrip`.

## [0.1.0] — initial

- ed2k link parse, `server.met` parse, ed2k/AICH/RED hashing.
- Single-source download with per-part MD4 verification.
- `ed2k-tool hash` / `serverlist` / `parse`.
