# eD2k 引擎 — 发布工作计划（Release Plan）

> **本文档定位**：项目距离「正式发布」的差距分析与完整工作计划，是**全项目进度的唯一权威索引**。
> 后续开发者据此了解「现在到哪了 / 还差什么 / 下一步做什么」。
>
> **更新协议（重要）**：
> - 每完成一个任务/子任务，把对应 `- [ ]` 改为 `- [x]`，并在【9. 变更日志】追加一行（日期 + 改动 + 提交 hash）。
> - 状态字段用：`✅ 已完成` / `🚧 进行中` / `⬜ 未开始` / `⛔ 阻塞` / `⏭️ 暂缓`。
> - 新增/变更阶段范围，先在【9. 变更日志】记录再改正文。
> - 本文档与 `docs/superpowers/specs|plans/` 的关系：那些是**单阶段**的设计/实现计划（已冻结的历史快照）；本文是**跨阶段、滚动更新**的总进度表。
>
> **最近更新**：2026-07-03

---

## 1. 项目总览

| 项 | 内容 |
|---|---|
| 项目目标 | 用现代 C++ 从零实现跨平台 eDonkey2000/eMule (eD2k) 下载引擎，最终具备完整客户端能力（下载、上传分享、Kademlia、协议混淆），交付形态 = **可嵌入 C++ 库 + 示例 CLI** |
| 当前版本 | `0.1.0`（`src/util/version.cpp`） |
| 技术栈 | C++20、Boost.Asio 协程、`tl::expected<T,std::error_code>`（协议热路径无异常）、GoogleTest、zlib、spdlog、CMake + vcpkg manifest、MSVC/VS2022 |
| 交付形态 | 静态库 `ed2k_core` + CLI `ed2k-tool` |
| 协议保真准则 | 字节对照 aMule 源码锁定，协议保真优先于实现简化（`prefer-best-over-simplest`） |

### 1.1 发布目标分层（采用「分阶段发布」策略）

| 版本（建议） | 里程碑 | 完成定义 | 状态 |
|---|---|---|---|
| **v1.0.0 MVP 下载器** | P4 收口（含 P4c-2/P4c-3）+ 发布工程 | P4c-2 AICH 互操作 + P4c-3 多源并发 + 真实服务器端到端下载（live 绿）+ README/打包/CI + 跨平台构建验证 | 🚧 差 P4c-3 + live 验证 + 发布工程（P4c-2 ✅） |
| v1.1 | P5 上传/分享 | 共享索引 + 上传队列 + 信用系统，成为「有来有往」节点 | ⬜ |
| v1.2 | P6 KAD | Kad 路由/bootstrap/搜索/取源/发布，无服务器找源 | ⬜ |
| v2.0 | P7 协议混淆 | TCP/UDP 协议混淆（RC4/MD5）+ 握手协商 | ⬜ |

> **为何分阶段**：项目已到「可下载」里程碑临界点（P4c-1 真实互操作代码已落地）。先发布可用下载器 v1.0，再增量补齐上传/KAD/混淆。
>
> **v1.0 范围决策（用户 2026-07-03 确认）**：P4c 全部工作（P4c-2 AICH 互操作 + P4c-3 多源并发）**必须在 v1.0 前完成**，与 R0 发布工程同属 v1.0 硬范围——详见 §4。

---

## 2. 路线图总览（P1–P7）

| 阶段 | 内容 | 里程碑 | 状态 | 证据 |
|---|---|---|---|---|
| **P1 地基** | L0：crypto/core/codec/hash/link/metfile/util + CLI hash/serverlist/parse | 纯本地单测全覆盖 | ✅ 已完成 | `215f37f` 起；`md4/sha1/ed2k_hasher/aich_hasher/server_met/known_part_met/tag/byte_io/link` 全套测试 |
| **P2 网络核** | L1：Asio 协程运行时、TCP 分帧收发、超时/取消、zlib inflate | 与 mock 回环测试 | ✅ 已完成 | `f303c7d` 设计；`net/{runtime,framing,connection,packet,inflate,udp_*}` |
| **P3 服务器协议** | L2：TCP 登录/HighID-LowID/搜索/取源/回调 + UDP 全局搜索/取源 | 首次上线连服务器搜文件拿源（mock） | ✅ 已完成 | P3a `d1e8c37` + P3b `57c9ced`；`server/{connection,messages,search_query,udp_*}` |
| **P4 下载引擎** | L3：C2C 握手、hashset 交换、块下载、part-MD4 校验、AICH 恢复、多源调度、断点续传 | ⭐ 首次端到端下载完整文件（MVP） | 🚧 部分完成 | 见 §3 |
| **P5 上传/分享** | L4：共享索引、向服务器发布、上传队列+信用系统 | 有来有往的节点 | ⬜ 未开始 | — |
| **P6 KAD** | L5：Kad 路由表、bootstrap(nodes.dat)、Kad 搜索/取源/发布 | 无服务器找源下载 | ⬜ 未开始 | — |
| **P7 混淆加密** | L6：TCP/UDP 协议混淆(RC4/MD5)、握手协商 | 兼容开启 obfuscation 的网络 | ⬜ 未开始 | — |

### P4 子阶段明细

| 子阶段 | 内容 | 状态 |
|---|---|---|
| P4a 下载引擎 | 单源 Download 编排 + PartFile part-MD4 校验 + 磁盘写 + gap 续传 + 块级多源（8MiB 帧限） | ✅ 已完成 |
| P4b 下载增强 | BlockAllocator + AICHChecker Merkle 校验 + MultiSourceDownload 骨架 | ✅ 已完成 |
| P4b AICH 恢复 | 扁平 AICH 块级损坏恢复（184320B 块）+ 同源重试 + e2e/单源测试 | ✅ 已完成 |
| **P4c-1 真实互操作** | `ed2k-tool` login/search/sources/download + server_session 编排 + LowID 回调框架（InboundListener + OP_CALLBACKREQUEST + peer_worker 分支）+ 门控 live 测试 | ✅ 已完成（代码） |
| **P4c-2 AICH 两级树互操作** | 真实 eMule AICH 两级树（OP_AICHFILEHASHREQ/ANS）+ `aich_hash_bytes` 回两级 + AICHChecker 两级 | ✅ M1✅ M2✅ M3✅ M4✅（opcode 已对 aMule 确认） |
| **P4c-3 多源并发 + 续传增强** | raccoon 多源并发 + 块粒度续传 + `peer::Block` u64 + 异步磁盘 I/O + .part.met 接入下载流程 | 🚧 M1✅ M2✅ M3✅ M4边界✅（raccoon 并发骨架+多源 e2e+.part.met 续传+异步磁盘卸载+>4GiB 边界）/ M4 live 待（需用户真实 eMule 服务器，spec✓ Block u64✓） |

---

## 3. 当前状态快照（2026-07-03）

### 3.1 构建 & 测试

```
cmake --build build/default --config Debug --target ed2k_tests ed2k-tool  → 成功
./ed2k_tests.exe                                                          → 218 tests, 210 PASSED, 3 DISABLED, 5 SKIPPED
```

> P4c-2 全里程碑 + P4c-3 M1 完成后：原 3 个 flat-model download AICH 用例已 re-enable 为两级 per-part（`BlockLevelAICHSingleSource`/`AICHCorruptionRecovers`/`AICHMasterMismatchDegrades`）；P4c-3 M1 新增 3 个多源并发 e2e（`MultiSourceBothFull`/`MultiSourceAggregates`/`MultiSourceSingleSubsetFails`）；M3 新增 2 个异步磁盘卸载（`MultiSourceAsyncDiskOffload`/`DiskExecutorRunsOnSeparateThread`）；M4 新增 `Beyond4GiBBoundaryRoundTrip`（>4GiB 边界，替代原 `RequestPartsI64RoundTrip` 占位 skip）。全套 225 绿，4 skip（仅 live）。

跳过的 4 个测试：
- `LiveServer.LoginReturnsId` / `SearchReturnsResults` / `GetSourcesReturnsOk` — **门控 live 测试**，`ED2K_LIVE` 未设故 skip
- `LiveDownload.HighIdSourceCompletes` — **门控 live 下载测试**，`ED2K_LIVE` 未设故 skip

> ⚠️ **关键风险**：4 个 live 测试**默认 skip，git 历史无「live 绿」提交记录**。P4c-1「真实互操作」在**代码层**已落地并 mock 回环全绿，但**从未在 CI/开发机上确认连真实 eMule 服务器跑绿**。这是 v1.0 发布前的**首要验证任务**（见 §5 R0）。

### 3.2 已实现能力清单

- **L0 基础原语**：MD4/SHA-1（自带实现，RFC1320/FIPS180 向量验证）、MD4Hash/AICHHash/IPv4、ByteReader/Writer（粘滞错误）、TLV Tag/TagList、ed2k 分块哈希（Red/Blue）、AICH SHA-1 Merkle、ed2k:// 链接解析、server.met/known.met/part.met 编解码 round-trip、错误码/spdlog
- **L1 网络核**：IoRuntime（单 io_context）、TCP 分帧（0xE3/0xC5/0xD4 + zlib inflate）、Connection（connect/send/recv/超时/取消）、UDP 分帧
- **L2 服务器协议**：ServerConnection（login/search/get_sources/callback/serverlist）、UDP 全局搜索/取源/stat/desc、SearchExpr 布尔树、服务器轮换+fallback
- **L3 下载引擎**：C2C 握手/hashset/filestatus/逐块下载、PartFile（part-MD4 校验+磁盘写+gap 续传+per-part block bitmap）、BlockAllocator（per-part 块分发）、AICHChecker（**两级 Merkle 标识符重建**，master-hash 协商降级）、MultiSourceDownload（**顺序单源**，非并发）、InboundListener（入站 C2C acceptor）、LowID 回调（OP_CALLBACKREQUEST + acceptor-mode 握手）
- **CLI**：`hash` / `serverlist` / `parse` / `login` / `search` / `sources` / `download`

### 3.3 已知技术债 / 未接线项

| # | 项 | 现状 | 归属 |
|---|---|---|---|
| D1 | `.part.met` / `known.met` API 存在但**未接入下载流程** | 续传靠重哈希数据文件（可用但慢） | P4c-3 |
| D2 | `MultiSourceDownload` **顺序单源**，非并发 | `download.cpp:189` 注释明示 raccoon 算法留后续 | P4c-3 |
| D3 | ~~`peer::Block.start/end` 为 **u32**，限单块 ~4GiB~~ | ✅ 已修复（P4c-3-3 `ed80bcc`）：Block u64 化，`decode_*_i64` >4GiB 窄化消除；`DecodeSendingPartI64Beyond4GiB` 锁定 | P4c-3 |
| D4 | ~~AICH 为**扁平单层** Merkle，与真实 eMule **两级树**不互操作~~ | ✅ 已修复（P4c-2 `de6d359`/`01432c1`/`2922515`）：两级 `aich_hash_bytes`+标识符重建 `AICHChecker`+V2 线协议+peer_worker master-hash 协商降级；3 两级 e2e 用例绿 | P4c-2 |
| D5 | LowID 回调路径在 **NAT 后无法 live 验证** | listener 框架 + 单测覆盖；公网机器才能全路径 | 后续（NAT 穿透/UPnP） |
| D6 | live 测试**从未确认绿** | 门控 skip，无绿记录 | R0（v1.0 首要） |
| D7 | **无 CI** | 无 `.github/workflows` | R0 |
| D8 | **无 README / 用户文档 / 安装说明** | 仅 design spec/plan | R0 |
| D9 | **仅 Windows/MSVC 验证** | 设计目标含 Linux/macOS | R0 |
| D10 | **无打包/安装产物** | 无 `install()` / vcpkg port / 二进制发布 | R0 |
| D11 | `encode_callback_request` 等曾为死代码 | P4c-1 已接线，需确认无残留死代码 | 收尾核查 |

---

## 4. 距离发布的差距分析

### 4.1 v1.0 MVP 下载器 — 完成定义（DoD）

v1.0 = **真实可用、可分发**的 eD2k 下载器。必须满足：

1. **真实互操作 live 验证绿**：`ED2K_LIVE=1` 下，`LiveServer.*` 三条 + `LiveDownload.HighIdSourceCompletes` 连真实 eMule 服务器跑通，下载完整文件 MD4 校验通过。（D6）
2. **跨平台构建**：Windows(MSVC) + Linux(GCC/Clang) 至少双平台 CMake+vcpkg 干净构建、测试全绿。（D9）
3. **CI**：PR/push 触发构建+测试（mock 回环必跑，live 门控手动）。（D7）
4. **用户文档**：README（简介/构建/用法/限制）、CLI 用法、公共 API 概览。（D8）
5. **打包**：CMake `install()` 目标 + 版本号升 `1.0.0`。（D10）
6. **P4c-2 AICH 两级树互操作完成**：与真实 eMule peer 两级 AICH 互操作，`OP_AICHFILEHASHREQ/ANS` 路径启用（取代 part-MD4 兜底）。✅ 完成（mock e2e 绿；live 真实 AICH 源留 R0-1）
7. **P4c-3 多源并发 + 续传增强完成**：raccoon 多源并发、`peer::Block` u64、`.part.met` 接入续传、异步磁盘 I/O。
8. **既有 mock 回环全绿不回归**。（已满足）

### 4.2 v1.0 范围内 P4c 工作的定位

用户 2026-07-03 决策：**P4c-2 与 P4c-3 均为 v1.0 硬范围，必须在 1.0 发布前完成（不可降级）。**

- **P4c-2 AICH 两级树互操作**：真实 eMule peer 多用两级 AICH。当前 part-MD4 兜底可下载，但损坏恢复弱、与开启 AICH 的 peer 不完全互操作。v1.0 必须启用 `OP_AICHFILEHASHREQ/ANS` 两级树路径。
- **P4c-3 多源并发 + 续传增强**：当前顺序单源（`download.cpp:189`），单 HighID 源可下载但速度/成功率受限。v1.0 必须完成 raccoon 多源并发、`peer::Block` u64、`.part.met` 接入续传、异步磁盘 I/O。

> 这意味着 v1.0 不是「尽快首发当前单源下载器」，而是「P4 完整收口后首发」。R0 发布工程可与 P4c-2/P4c-3 **并行**推进，但 v1.0 发布门在 P4c-2 + P4c-3 + R0 全部完成之后。
> 建议内部里程碑：`v0.2.0`=P4c-2 完成，`v0.3.0`=P4c-3 完成，`v1.0.0`=R0 收口 + live 绿。

### 4.3 完整客户端（v2.0）— 完成定义

v1.0 + P5（上传/分享）+ P6（KAD）+ P7（协议混淆）全部完成，达到设计文档 §1 的「完整客户端能力」。

---

## 5. 工作计划（分阶段任务）

> 任务编号：`R0`（发布工程）/ `P4c-2` / `P4c-3` / `P5` / `P6` / `P7`。
> 每个任务带状态 checkbox，完成即勾选并在 §9 记录。
> 依赖关系见各阶段首行「依赖」。

### 阶段 R0 — 发布工程基线（v1.0 关键路径）

**依赖**：无（可与 P4c-2/P4c-3 并行）
**目标**：把「能跑的代码」变成「能发布的产品」。

- [ ] **R0-1 live 真实互操作验证**【v1.0 首要】
  - 设 `ED2K_LIVE=1 ED2K_SERVER=<可达服务器> ED2K_LINK=<测试链接> ED2K_EXPECT_MD4=<期望>` 跑 4 个 live 测试。
  - 8 个内建 fallback 服务器（见 P4c-1 spec §6.5）：45.82.80.155:5687 等。
  - 需先调研一个**长期有 HighID 源、size<100MB** 的测试 ed2k 链接（P4c-1 M2 前置依赖，未完成）。
  - 失败则按 aMule 源码逐字节排查登录/hashset/blocks 帧（P4c-1 spec §3.5/§4.6 风险点清单）。
  - 产出：live 绿记录写入 §9 + 测试链接固化到文档（非代码硬编码）。
- [ ] **R0-2 CI 流水线**
  - `.github/workflows/build.yml`：Windows(MSVC)+Ubuntu(GCC) 矩阵，vcpkg manifest 安装，`cmake --preset default` + build + `ctest`。
  - live 测试默认 skip（不依赖外网）；可选定时 job 跑 live（容忍失败）。
- [ ] **R0-3 跨平台构建验证**
  - Linux/macOS 构建：排查 MSVC 特有用法（`_WIN32_WINNT`、Winsock 头、路径分隔）。
  - 目标：双平台 `ed2k_tests` 全绿（live skip）。
- [ ] **R0-4 README + 用户文档**
  - `README.md`：项目简介、协议覆盖范围、构建（vcpkg/CMake）、CLI 用法、当前限制（NAT/LowID/AICH）。
  - `docs/USAGE.md`：CLI 各子命令详解 + ed2k 链接示例。
  - `docs/API.md`：公共 API（`include/ed2k/` 公开头）概览。
- [~] **R0-5 打包与版本**（install/export 已完成 2026-07-03；版本号待 release 时升 1.0.0）
  - [x] `CMakeLists.txt` `install(TARGETS ed2k_core ed2k-tool EXPORT ed2kTargets)` + 公共头安装 + `ed2k::` 目标导出 + `BUILD_INTERFACE/INSTALL_INTERFACE` include 修复。
  - [ ] `version.cpp` 升 `1.0.0`（release 时）；`project(VERSION 0.1.0)` 已就位。
  - [ ] （可选）vcpkg port / Release 二进制。
- [ ] **R0-6 死代码/收尾核查**
  - 确认 `encode_callback_request` 等已全接线（D11）；`RequestPartsI64RoundTrip` skip 是否可修复或永久登记。

### 阶段 P4c-2 — AICH 两级树互操作（v1.0 硬范围）

**依赖**：P4b AICH 恢复（已完成）
**目标**：与真实 eMule peer 的两级 AICH 树互操作，启用 `OP_AICHFILEHASHREQ/ANS` 证明路径。

- [x] **P4c-2-1 设计 spec**（✅ 2026-07-03，修订 `9cbd1cd`）：`docs/superpowers/specs/2026-07-03-ed2k-p4c2-aich-interop-design.md`。两级 Merkle 树论点已对 aMule `SHAHashSet.{h,cpp}` 逐行确认（分裂规则 `nLeft=((isLeft?nBlocks+1:nBlocks)/2)*baseSize`、baseSize 切换、hash identifier）。**opcode/帧字节已全部对 aMule 源码确认**（`TCP.h`+`DownloadClient.cpp`+`ClientTCPSocket.cpp`）：`AICHREQUEST=0x9B`/`AICHANSWER=0x9C`（原代码 0x61/0x62 错）、`AICHFILEHASHREQ=0x9E`/`AICHFILEHASHANS=0x9D`、协议层 `OP_EMULEPROT`(0xC5)（原 eDonkey 0xE3 错）、`OP_AICHREQUEST` 帧 = file_hash(16)+part_index(u16)+master_hash(20)、`OP_AICHANSWER` 帧含 part_index(u16)。四里程碑 M1（两级哈希+测试向量）/M2（AICHChecker 两级验证）/M3（线协议编解码+C2CConnection）/M4（peer_worker 集成+per-part 块分解+mock e2e）。**⚠️ M4 的 per-part 块分解与 P4c-3 flat 块假设冲突——见 §7。**
- [x] **P4c-2-2 实现计划**（✅ 2026-07-03）：`docs/superpowers/plans/2026-07-03-ed2k-p4c2-aich-two-level-impl-plan.md`。3 阶段 S1（M1+M2 两级哈希+校验，合并因 `aich_checker_test` 用 `aich_hash_bytes` 当 oracle 耦合）/S2（M3 线协议字节修正）/S3（M4 per-part 块+peer_worker+mock e2e，P4c-2→P4c-3 块模型门）+ 10 项陷阱清单（G1-G10）+ 每阶段测试门 + 既有测试破改分析。
- [x] **P4c-2-3 `aich_hash_bytes` 回两级**（✅ 2026-07-03，M1）：扁平 lone-child Merkle → 两级平衡二叉树（顶层 PARTSIZE base → 底层 EMBLOCKSIZE base），`build_subtree` 递归对照 aMule `SHAHashSet.cpp:118-119` 分裂规则（left-biased ceil/floor、baseSize 切换、叶 `data_size<=base_size`）；新增 `PART_SIZE=9728000` 常量。测试：`TwoLevelThreeBlocksMatchesManual`（3 块巧合同根锚点）+ `TwoLevelFourBlocksMatchesManual`（偶数 split）+ `TwoLevelMultiPartMatchesReference`（2/3 part 独立参考实现 `ref_two_level` 交叉校验 + 断言两级≠扁平）；`aich_checker_test` 单 part 巧合仍绿。**⚠️ 发现 M1↔M4 download 耦合（G11）**：3 个 flat-model download AICH 用例（`AICHCorruptionRecovers`/`BlockLevelAICHSingleSource`/`AICHWrongRootFails`）因 flat 块叶跨 part 边界与两级 per-part 叶不一致而失效，`DISABLED_` 待 M4（P4c-2-6）per-part 改写。全套 212 绿 + 3 DISABLED + 5 skip。
- [x] **P4c-2-4 `AICHChecker` 两级校验**（✅ 2026-07-03，M2）：`AICHChecker(root, file_size)`（两级树结构由 file_size 推导）；`verify_block(block_index, data, proof)` 两级 byte-offset 递归 `walk`（left-biased split、baseSize 切换、真二叉树无 lone-child），block_index 语义改两级叶序 part-major。**⚠️ 偏离计划**：保留 `(block_index, data, span<Digest>)` 签名（原计划 `(part_index, block_in_part, AICHProofHash)` 会迫使 download.cpp 提供 part-local 索引 → 需 M4，见 G11），`(part_index,…)` + identifier 重建推迟 M4。`download.cpp` 构造参数 `num_blocks→size`（1 行）。测试：8 既有用例改两级 `proof_for` + `(hash, file_size)` 构造；新增 `MultiPartProofPath`（2-part，part0 首/末短块 + part1 块 + 篡改/越界失败）。全套 213 绿 + 3 DISABLED + 5 skip。
- [x] **P4c-2-5 线协议编解码 + C2CConnection**（✅ 2026-07-03，M3）：改 `AICHREQUEST/ANSWER`=0x9B/0x9C、新增 `AICHFILEHASHREQ/ANS`=0x9E/0x9D、协议层改 `proto::eMule`(0xC5)（原 eDonkey 0xE3 错）；重写 `encode_aich_request(FileHash,AICHHash master,u16 part_index)`→38B（file_hash→part_index→master_hash，对照 aMule `SendAICHRequest:1614-1618`）+ `decode_aich_answer→expected<AICHRecoveryData>`（V2 recovery data：count16+[ident16+hash]+count32+[ident32+hash]，对照 `ReadRecoveryData`）；新增 `encode_aich_file_hash_req`/`decode_aich_file_hash_ans` + `request_aich_master_hash`；`request_aich_proof` 增 master_hash 回显校验（`DownloadClient.cpp:1634`，不一致→`hash_mismatch`）。`AICHProofHash`/`AICHRecoveryData` 结构。**耦合**：`request_aich_proof` 签名变更迫使 `download.cpp:165` 调用点同步（master=`*aich`、part_index 暂用 flat `global` 占位、proof 按 wire 原序取 span 喂 M2 `verify_block`，M4 改真实 part_index + 标识符重建）。测试：messages +3（file_hash_req/ans、38B 字节断言、V2 解码+truncated）、connection +2（master_hash round-trip、master mismatch），并修 `sha1_from_hex` helper 只填 10 字节的旧 bug。全套 210 绿 + 3 DISABLED + 5 skip。
- [x] **P4c-2-6 `peer_worker` 启用 AICH + per-part 块**（✅ 2026-07-03，M4）：M4a（`de6d359`）`BlockAllocator`/`PartFile` 改 per-part 块分解（块不跨 part 边界，`next_block→(part,bip,start,end)`），`Download::run`+`peer_worker` per-part 嵌套，删 `num_blocks<=65535` 守卫（G10），6 block_allocator + 8 part_file 测试改写。M4b（`01432c1`）`AICHChecker` 标识符重建两级 `verify_block(part_index, block_in_part, data, span<AICHProofHash>)`——两步安全验证：叶 `SHA1(data)==map[leaf_ident]` + 根 `rebuild(file)==master`（ident=root→叶 MSB-first 路径，左子=`(ident<<1)|1`/右子=`ident<<1`，rebuild 复用 proof 提供的叶/兄弟 part-root hash）；`download.cpp` 调用点改真实 u16 part_index。9 aich_checker 测试改写（`recovery_for` 对照 aMule `CreatePartRecoveryData`）。
- [x] **P4c-2-7 测试**（✅ 2026-07-03，M4c，`2922515`）：mock 两级 AICH round-trip + master hash 不匹配降级。`serve_aich_peer` 改 V2（OP_AICHFILEHASHANS 真实两级 master + OP_AICHANSWER V2 恢复数据，recovery_for 按 part 预计算缓存）。`peer_worker` master-hash 协商降级（OP_AICHFILEHASHREQ→ANS 比对 *aich，不匹配/不支持→降级无 AICH，对照 aMule）。3 用例 re-enable：`BlockLevelAICHSingleSource`（匹配 master+干净→完成）、`AICHCorruptionRecovers`（part0 块5 坏数据→verify 失败→block_corrupt；C2 先验证后写入坏块从未落盘；peer B 续传完成）、`AICHMasterMismatchDegrades`（原 AICHWrongRootFails 改：错误 root+正确 master→降级→成功）。perf(net): c2c socket 设 TCP_NODELAY（AICH 短帧请求-应答避 Nagle+delayed-ACK 停顿，AICH 单源 57s→2.9s）。全套 221 绿 + 5 skip。live（真实 AICH 源）留 R0-1。

### 阶段 P4c-3 — 多源并发 + 续传增强（v1.0 硬范围）

**依赖**：P4a/P4b（已完成）
**目标**：raccoon 多源并发下载 + 块粒度续传 + 大文件支持 + 异步磁盘。

- [x] **P4c-3-1 设计 spec**（✅ 2026-07-03）：`docs/superpowers/specs/2026-07-03-ed2k-p4c3-multisource-design.md`。四里程碑 M1（raccoon 骨架 + `peer::Block` u64 + 共享 BlockAllocator）/ M2（`.part.met` 续传接入）/ M3（异步磁盘 I/O）/ M4（live + >4GiB 边界）。并发原语 = 同步 `BlockAllocator::next_block()` 块分发 + `asio::experimental::channel` 完成信号，**禁用 `condition_variable`** 以避免单线程 io_context 死锁（破除 `download.cpp:190-191` 注释约束）。AICH 路径不动（属 P4c-2）。
- [x] **P4c-3-2 实现计划**（✅ 2026-07-03）：`docs/superpowers/plans/2026-07-03-ed2k-p4c3-raccoon-impl-plan.md`。M1 拆 4 个 green-deployable 阶段（S1 `fetch_hashset`+`SharedState` 脚手架 / S2 共享状态 `peer_worker`+setup 顺序 / S3 raccoon 并发+源耗尽处理 / S4 多源 mock e2e）+ 10 项陷阱清单 + 每阶段测试门。M2/M3/M4 待 M1 落地另起。
- [x] **P4c-3-3 `peer::Block` u32→u64**（✅ 2026-07-03，`ed80bcc`）：解除单块 ~4GiB 限制（D3 清偿）。`decode_sending_part_i64`/`decode_compressed_part_i64` 的 u64→u32 隐式窄化消除；`PartFile::write_block` 签名 u64（body 本就 u64 内部）；新增 `DecodeSendingPartI64Beyond4GiB` 锁定 >4GiB 偏移；214 测试 209 过 5 skip 不回归。
- [x] **P4c-3-4 跨源共享 BlockAllocator**（✅ 2026-07-03，`5187ff2`）：`SharedState{PartFile,BlockAllocator,AICHChecker,first_err,active_workers}` 跨 worker 共享；单网络线程 → `mark_block_done`/`first_err` 直写无锁；新增 `BlockAllocator::next_block_for_parts(has_part)` per-part 位图过滤分发（worker 仅请求对端有该 part 的块, 源耗尽返回 nullopt）。
- [x] **P4c-3-5 raccoon 调度**（✅ 2026-07-03，`5187ff2`）：`MultiSourceDownload::run` 改 N worker `co_spawn(detached)` 并发编排, 替换顺序单源（破除 `download.cpp:189-191` 注释约束）；完成信号 = `asio::experimental::channel<void(boost::system::error_code,int)>`（leading ec 为 op-status, int 忽略; 错误经 `st.first_err` 单线程直写; **禁用 condition_variable** 防单 io_context 死锁）；setup 连接复用 spec §1.4（fetch_hashset 的 live 连接复用给 worker[setup_idx], 规避 MockPeer 单 accept 限）。
- [x] **P4c-3-6 `.part.met` 接入下载流程**（✅ 2026-07-03，`0cf959a`，M2）：`PartFile` met-first 续传——构造时若 `.part.met` 有效（magic+hash+part_hashes 匹配）→ 按 gaps 恢复 `part_done_`/`block_done_` **无需重哈希**（D1 性能清偿）；缺失/损坏/陈旧 → 回退 `rehash_all`（P4a 安全网）。`write_block` part 完成时 `save_met()` 落盘。信任模型：met 标 done 的 part 直接受信（写盘时已 MD4 校验），仅 `file_size>=part_end` 防截断，不回读重哈希。partial part 重下整 part（块级不持久化，与 P4a 一致）。测试 +3（`ResumeFromPartMetTrustedOverCorruptData`/`CorruptPartMetFallsBackToRehash`/`StalePartMetHashMismatchIgnored`），全套 222/227/5。**注**：`.part.met` 格式为内部 round-trip（非 aMule 字节级）；跨客户端续传（aMule-faithful `.part.met`）经用户 scope 决策延后，非 v1.0 硬范围（D1 为性能目标）。格式隔离在 `parse/write_part_met`，后续可换 aMule-faithful 而不动 `download.cpp`。
- [x] **P4c-3-7 异步磁盘 I/O**（✅ 2026-07-03，M3）：磁盘写 + part-MD4 readback 卸载到独立 disk 线程（`IoRuntime::disk_executor()` = `asio::thread_pool{1}`，单线程串行化 `f_` 无须 strand；设计 §3 并发模型）。`PartFile::write_block_async(start,end,data,disk_ex)`——网络线程只改状态、disk 线程做 `f_.seekp/write` 与 readback+MD4；两步 hop 用 `asio::post(ex, bind_executor(ex, use_awaitable))` **强制 resume 于目标 executor**（裸 `post(ex, use_awaitable)` 会 resume 于协程关联 executor=网络线程，无卸载——`DiskExecutorRunsOnSeparateThread` 锁定该陷阱）。`MultiSourceDownload::set_disk_executor` 注入 disk 池，默认 = 网络线程（同步等效，既有测试零破改）。`SharedState` 透传 `disk_ex`，`peer_worker` 写盘点改 `write_block_async`。测试 +2（`MultiSourceAsyncDiskOffload` 真实 disk 卸载 e2e + `DiskExecutorRunsOnSeparateThread` 线程 ID 结构断言）。全套 229 绿 + 5 skip。
- [x] **P4c-3-8 测试（M1 部分）**（✅ 2026-07-03，`7fd040e`）：多源并发 mock e2e — `serve_subset_peer`（per-part 位图 FILESTATUS）+ `MultiSourceBothFull`（两满源并发无块丢失/重复）+ `MultiSourceAggregates`（A=part0/B=part1 互补 per-part 聚合完成整文件）+ `MultiSourceSingleSubsetFails`（单源仅 part0 反证 io_error）。测试门 219/224/5（≥222/≥217/5）。续传 round-trip（M2）+ >4GiB 边界（M4）待落地。
- [x] **P4c-3-8 测试（M2 部分）**（✅ 2026-07-03，`0cf959a`）：`.part.met` 续传 round-trip — 3 个 met-vs-rehash 分歧测试（见 P4c-3-6）。>4GiB 边界（M4）待落地。
- [x] **P4c-3-8 测试（M3 部分）**（✅ 2026-07-03，M3）：异步磁盘卸载 — `MultiSourceAsyncDiskOffload`（注入真实 disk 池，多源 e2e 完成 + PartFile complete）+ `DiskExecutorRunsOnSeparateThread`（线程 ID 断言 disk≠net，锁定 `post+bind_executor` 卸载前提）。>4GiB 边界（M4）待落地。
- [x] **P4c-3-8 测试（M4 部分：>4GiB 边界）**（✅ 2026-07-03，M4）：`Beyond4GiBBoundaryRoundTrip`——`file_size=4GiB+2*PART`（part 442 整个 >4GiB），仅下载 part 442（满 part 53 块，~9.7MB；PartFile 稀疏创建，预写 `.part.met` 全 gap 跳过 rehash_all 规避 444 part × 9.7MB 冷启动开销）。验证 u64 偏移在 `BlockAllocator→encode_request_parts_i64→PartFile.seekp/write/readback/MD4` 全路径不发生 u32 窄化（D3 根因）：每块 `start>4GiB` 断言、I64 wire round-trip 高位非零、part 满 MD4 通过 → `gaps()` 不含 part 442、磁盘逻辑大小 >4GiB。替代原 `RequestPartsI64RoundTrip` 占位 skip（i64 round-trip 在此真实执行）。全套 225 绿 + 4 skip（仅 live）。
- [ ] **P4c-3-8 测试（剩余）**：M4 live 验证（需用户真实 eMule 服务器环境，R0-1）。

> **P4c-3 M1+M2+M3+M4(边界) 验收 ✅**（2026-07-03）：raccoon 多源并发骨架（S1–S4）+ `.part.met` 续传接入 + 异步磁盘 I/O 卸载 + >4GiB 边界全绿，225/229/4。**剩余 v1.0 硬范围**：仅 M4 live 验证（需用户真实 eMule 服务器环境，R0-1）。

### 阶段 P5 — 上传/分享（v1.1）

**依赖**：v1.0（含 InboundListener，P4c-1 M3 已铺路）
**目标**：共享索引、向服务器发布、上传队列 + 信用系统。

- [ ] **P5-1 设计 spec**：L4 架构（共享索引、SourceExchange、上传队列、信用系统）。
- [ ] **P5-2 实现计划**。
- [ ] **P5-3 共享索引 + known.met 语义填充**：`hash_file` 扫已下载文件建索引（P1 已有编解码，缺语义）。
- [ ] **P5-4 向服务器发布共享**：`OP_OFFERFILES`。
- [ ] **P5-5 上传队列 + 信用系统**：入站 peer 的 ACCEPTUPLOADREQ 调度。
- [ ] **P5-6 SourceExchange**：C2C 源交换（`OP_ASKSHAREDFILES`/`OP_SHAREDFILES`）。
- [ ] **P5-7 测试**：mock 上传回环 + live（公网机器）。

### 阶段 P6 — KAD（v1.2）

**依赖**：P5（可选，KAD 可独立于上传）
**目标**：无服务器找源下载。

- [ ] **P6-1 设计 spec**：Kad 路由表（k-bucket）、bootstrap（nodes.dat）、Kad 搜索/取源/发布、KAD UDP 协议。
- [ ] **P6-2 实现计划**。
- [ ] **P6-3 Kad 路由表 + bootstrap**。
- [ ] **P6-4 Kad 搜索/取源/发布**。
- [ ] **P6-5 `nodes.dat` 读写**（P1 非目标，此处实现）。
- [ ] **P6-6 测试**：mock Kad 回环 + live bootstrap。

### 阶段 P7 — 协议混淆/加密（v2.0）

**依赖**：P2/P3/P4（协议层稳定）
**目标**：兼容开启 obfuscation 的网络。

- [ ] **P7-1 设计 spec**：TCP/UDP 协议混淆（RC4 keystream from MD5）+ 握手协商。
- [ ] **P7-2 实现计划**。
- [ ] **P7-3 MD5/RC4 自带实现**（P1 非目标，此处实现）。
- [ ] **P7-4 混淆握手 + 帧加解密**。
- [ ] **P7-5 测试**：mock 混淆回环 + live（连开启 obfuscation 的服务器/peer）。

---

## 6. v1.0 发布检查清单（Release Checklist）

发布 v1.0 前逐项 ✅：

- [ ] R0-1 live 4 测试绿（真实服务器下载完整文件 MD4 校验通过）
- [ ] R0-2 CI 双平台绿（mock 全过，live skip）
- [ ] R0-3 Linux + Windows 双平台构建+测试通过
- [ ] R0-4 README/USAGE/API 文档完成
- [~] R0-5 `install()` ✅（ed2k_core+ed2k-tool+头+ed2k:: 导出，2026-07-03）+ 版本号 `1.0.0`（release 时升）
- [ ] R0-6 死代码清理、skip 项登记
- [x] P4c-2 AICH 两级树互操作完成（OP_AICHFILEHASHREQ/ANS + 两级 Merkle + peer_worker 启用 AICH）
- [~] P4c-3 多源并发 + 续传增强完成（raccoon ✅ + Block u64 ✅ + .part.met 接入 ✅ + 异步磁盘 ✅ + >4GiB 边界 ✅；剩 M4 live 验证，需用户真实 eMule 服务器=R0-1）
- [ ] 既有 mock 回环全绿不回归（213→含新增，仅预存 skip）
- [ ] CHANGELOG / Release notes

---

## 7. 依赖与关键路径

```
v1.0 关键路径（P4c-2/P4c-3 为硬前置）：
  P4c-2(AICH 互操作) ──┐
  P4c-3(多源并发)    ──┤
  R0-1(live 验证)    ──┼──► R0-2(CI) ──► R0-3(跨平台) ──► R0-4/5(文档/打包) ──► v1.0
                       │
                       └─ R0-1 live 若暴露协议 bug → 反向触发 P4c-2/P4c-3 或协议 hotfix

  注：R0 发布工程可与 P4c-2/P4c-3 并行；但 v1.0 发布门 = P4c-2 + P4c-3 + R0 全部完成。
  建议内部里程碑：v0.2.0=P4c-2 完成，v0.3.0=P4c-3 完成，v1.0.0=R0 收口+live 绿。

v1.0 ──► P5(上传) ──► v1.1
v1.0 ──► P6(KAD) ──► v1.2   (P6 可与 P5 并行)
v1.0 ──► P7(混淆) ──► v2.0
```

**关键风险点**：R0-1 live 验证是最大不确定性——mock 全绿不代表真实帧兼容。P4c-1 spec §3.5/§4.6 已列风险点（登录 tag 编码、hashset 布局、REQUESTPARTS 三区间、COMPRESSEDPART、排队等待）。live 失败可能反向触发 P4c-2/P4c-3 或协议 hotfix。

> **⚠️ P4c-2 ↔ P4c-3 块模型依赖（评审 P4c-2 spec 发现；修订 spec `9cbd1cd` §7.3 确认集成点）**：P4c-2 spec **M4** 要求下载块从 **flat 全文件块（块可跨 part 边界）** 回退为 **per-part 块（每 part 53 块、末块对齐 part 边界）**——否则块 SHA-1 与真实 eMule peer 的 AICH 树叶不匹配，interop 不可能。而 P4c-3 spec/计划当前假设 flat 块（`global = start/AICH_BLOCK_SIZE`）。**两者块模型不兼容，且共享 `BlockAllocator`/`PartFile` 基础设施。** 建议执行顺序：**先做 P4c-2 的 M4 per-part 块分解 + 两级 AICH（M1→M2→M3→M4），再在其上做 P4c-3 raccoon**（raccoon 并发模型与块模型正交——P4c-2 spec §7.3 明示「P4c-3 的 raccoon 并发不改 AICH 校验逻辑，两者正交」，但实现共享 `BlockAllocator`/`PartFile`，须在 per-part 块上构建；`next_block()` 返回值多一个 `part_index` 字段）。P4c-3 计划 S1–S4 的 flat 块假设须在 P4c-2 M4 落地后修订为 per-part。即 §7 图中 P4c-2 与 P4c-3 **非完全并行**——块模型层有 P4c-2→P4c-3 的前置。

---

## 8. 风险登记

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| live 测试连真实服务器失败（协议帧不兼容） | 中 | 高（阻塞 v1.0） | 逐字节对照 aMule；每修一处立即 live 复验；P4c-1 spec 已列风险点 |
| 找不到长期可用的 HighID 测试源 | 中 | 中 | 8 个 fallback 服务器轮换；测试文件降级为握手测试 |
| NAT 后 LowID 路径无法 live 验证 | 高（已知） | 低（单测覆盖） | D5 如实记录；公网机器全路径；v1.0 不强求 LowID live |
| 跨平台构建暴露 MSVC 特有依赖 | 中 | 中 | R0-3 早期验证；隔离平台代码 |
| 多源并发单线程 io_context 死锁 | 中 | 中（P4c-3） | co_spawn 多协程 + 共享无锁状态，禁用 condition_variable（`download.cpp:191` 注释） |
| 服务器全死/外网不稳定 | 中 | 低 | live 门控 skip，不阻塞 CI；mock + 单测保底 |

---

## 9. 变更日志

| 日期 | 改动 | 提交 / 负责 |
|---|---|---|
| 2026-07-03 | 初始创建：路线图状态核对（P1–P4c-1 ✅，P4c-2/3/P5/P6/P7 ⬜）、差距分析、分阶段工作计划、v1.0 检查清单 | 147d891 |
| 2026-07-03 | 用户决策：P4c-2/P4c-3 由「软范围」升为 **v1.0 硬范围**（1.0 前必须完成，不可降级）。更新 §1.1/§4.1/§4.2/§5/§6/§7；新增内部里程碑 v0.2.0/v0.3.0 | 147d891 |
| 2026-07-03 | /loop 启动：编排 v1.0 关键路径。R0-5 完成（CMake install/export + BUILD/INSTALL_INTERFACE 修复，configure/build/测试绿）。P4c-2-1/P4c-3-1 设计 spec 派子代理起草中 | 9051eb8 |
| 2026-07-03 | P4c-3-1 完成：多源并发设计 spec 评审通过并提交（`docs/superpowers/specs/2026-07-03-ed2k-p4c3-multisource-design.md`，四里程碑 M1–M4，`asio::experimental::channel` 完成信号避单线程 io_context 死锁）。P4c-2-1 子代理（前次 compaction 后失效）重新派发 | 6381985 |
| 2026-07-03 | P4c-3-3 完成：`peer::Block` u32→u64（`ed80bcc`），消除 `decode_*_i64` >4GiB 窄化（D3 清偿）；新增 `DecodeSendingPartI64Beyond4GiB`；214 测试 209 过 5 skip 不回归 | ed80bcc |
| 2026-07-03 | P4c-3-2 完成：M1 raccoon 实现计划（`docs/superpowers/plans/2026-07-03-ed2k-p4c3-raccoon-impl-plan.md`），4 阶段 S1–S4 + 10 项陷阱清单 + 测试门 | 7c623d7 |
| 2026-07-03 | P4c-2-1 完成：AICH 两级树互操作设计 spec 评审通过（`docs/superpowers/specs/2026-07-03-ed2k-p4c2-aich-interop-design.md`，B1-B8 已核对代码，三里程碑 M1-M3）。**发现 B8 与 P4c-3 块模型冲突**——P4c-2 要求 per-part 块、P4c-3 假设 flat 块；建议 P4c-2 C3 回退先于 P4c-3 raccoon（见 §7） | 828f655 |
| 2026-07-03 | P4c-2 spec 修订（`9cbd1cd`）：重构为四里程碑 M1-M4（两级哈希/AICHChecker 两级/线协议/peer_worker+per-part 块）；**opcode 与帧字节全部对 aMule 源码确认**——`AICHREQUEST/ANSWER`=0x9B/0x9C（原 0x61/0x62 错）、`AICHFILEHASHREQ/ANS`=0x9E/0x9D、协议层 eMule 0xC5（原 eDonkey 错）、帧顺序 file_hash→part_index→master_hash、`AICHANSWER` 含 part_index；两级树论点对 `SHAHashSet.{h,cpp}` 逐行确认。RELEASE-PLAN 同步：P4c-2 状态 M1-M3→M1-M4、§7 B8/C3→M4、P4c-2-1/-3..7 行按 M1-M4 重映射（`13fa676`） | 9cbd1cd |
| 2026-07-03 | P4c-2-2 完成：两级 AICH 实现计划（`docs/superpowers/plans/2026-07-03-ed2k-p4c2-aich-two-level-impl-plan.md`），3 阶段 S1（M1+M2 合并：`aich_checker_test` 用 `aich_hash_bytes` 当 oracle 故耦合）/S2（M3 线协议）/S3（M4 per-part 块，P4c-2→P4c-3 块模型门）+ G1-G10 陷阱 + 既有测试破改分析（`FlatMerkleTwoChunkMatchesManual` 必破、3 块巧合同根）。回填 `13fa676` | 2a0a9df |
| 2026-07-03 | P4c-2-3 完成（M1）：`aich_hash_bytes` 扁平→两级 `build_subtree`（对照 aMule `SHAHashSet.cpp:118-119` 分裂规则）+ `PART_SIZE` 常量；`aich_hasher_test` 改写（3/4 块手算锚点 + 多 part `ref_two_level` 参考交叉校验 + 两级≠扁平断言）。**发现 G11（M1↔M4 download 耦合）**：flat 块叶跨 part 边界与两级 per-part 叶不一致 → 3 个 flat download AICH 用例 `DISABLED_` 待 M4 per-part 改写。全套 212 绿 + 3 DISABLED + 5 skip。计划 S1 测试门 + G11 同步更新 | 5df92ce |
| 2026-07-03 | P4c-2-4 完成（M2）：`AICHChecker(root, file_size)` + 两级 byte-offset `walk`（left-biased split、真二叉树无 lone-child）；`verify_block` 签名保留 `(block_index, data, span<Digest>)`，`(part_index, block_in_part, AICHProofHash)` 推迟 M4（G11 避免 download.cpp part-local 耦合）；`download.cpp` 构造 `num_blocks→size`。`aich_checker_test` 改两级 `proof_for`/`subtree_root` + 新增 `MultiPartProofPath`（2-part part0 末短块 + part1 块）。S1 DoD 勾除。全套 213 绿 + 3 DISABLED + 5 skip | e7a5899 |
| 2026-07-03 | P4c-2-5 完成（M3）：AICH 线协议对齐 aMule V2 帧——`AICHREQUEST/ANSWER`=0x9B/0x9C、新增 `AICHFILEHASHREQ/ANS`=0x9E/0x9D、协议层 `proto::eMule`(0xC5)（原 eDonkey 错）；`encode_aich_request`→38B（file_hash→part_index→master_hash）、`decode_aich_answer→AICHRecoveryData`（V2 count16/32+ident+hash）、`encode_aich_file_hash_req`/`decode_aich_file_hash_ans`、`request_aich_master_hash`、`request_aich_proof` 增 master 回显校验。`download.cpp:165` 调用点同步（part_index 暂用 flat global 占位，M4 改）。测试 +5（38B 字节断言/V2 解码/file_hash req-ans/master 交换/master mismatch）+ 修 `sha1_from_hex` 只填 10 字节旧 bug。全套 210 绿 + 3 DISABLED + 5 skip | 359c28f |
| 2026-07-03 | P4c-2-6 完成（M4a，`de6d359`）：`BlockAllocator`/`PartFile` 扁平整文件块→per-part 块模型（块绝不跨 part 边界，`next_block→(part_index,block_in_part,start,end)`，`end` 按 part 边界截断）；`Download::run`+`peer_worker` per-part 嵌套循环；删 `num_blocks<=65535` 守卫（G10，part_index u16 自然有界）。`block_allocator_test`(6)/`part_file_test`(8) 改 per-part（含 part0 末块 part 边界对齐、PartFile 恢复 block_done_）。全套 218 绿 + 3 DISABLED + 5 skip | de6d359 |
| 2026-07-03 | P4c-2-6 完成（M4b，`01432c1`）：`AICHChecker` 标识符重建两级 `verify_block(part_index, block_in_part, data, span<AICHProofHash>)`——两步安全验证（叶 `SHA1(data)==map[leaf_ident]` 块完整性 + 根 `rebuild(file)==master` 证明绑定受信 master）。标识符=root→叶 MSB-first 路径（左子 `(ident<<1)|1`/右子 `ident<<1`/根 1 排除），split_children 对照 aMule `SHAHashSet.cpp:118-119` 左偏分裂，rebuild 复用 proof 提供的叶/兄弟 part-root hash（不重算叶数据）。`download.cpp` 调用点改真实 u16 part_index + `span<AICHProofHash>`。`aich_checker_test`(9) 改写：`recovery_for`（`CreatePartRecoveryData` 对偶：兄第 part-root+part 全叶带 ident）+ 两步验证用例（good/bad/right-child/lone-last/tampered-leaf/short/wrong-master/missing-leaf/2-part path）。全套 218 绿 + 3 DISABLED + 5 skip | 01432c1 |
| 2026-07-03 | P4c-2-7 完成（M4c，`2922515`）：`peer_worker` master-hash 协商降级（OP_AICHFILEHASHREQ→ANS 比对 *aich，不匹配/不支持→降级无 AICH，对照 aMule）。`serve_aich_peer` 改 V2（OP_AICHFILEHASHANS 真实两级 master + OP_AICHANSWER V2 恢复数据，recovery_for 按 part 预计算缓存避逐块重算）。3 用例 re-enable：`BlockLevelAICHSingleSource`/`AICHCorruptionRecovers`（C2 先验证后写入坏块从未落盘）/`AICHMasterMismatchDegrades`（原 AICHWrongRootFails 改：错误 root+正确 master→降级→成功）。perf(net): c2c socket TCP_NODELAY（AICH 短帧避 Nagle+delayed-ACK 停顿，单源 57s→2.9s、损坏恢复 91s→6.3s）。全套 221 绿 + 5 skip。**P4c-2 全里程碑完成** | 2922515 |
| 2026-07-03 | P4c-3 M1 完成（raccoon 并发骨架，`5187ff2`+`7fd040e`）：`MultiSourceDownload::run` 改 N worker `co_spawn(detached)` 并发（破除顺序单源 `download.cpp:189-191`）；`SharedState` 跨 worker 共享 `PartFile`/`BlockAllocator`/`AICHChecker`（单网络线程→`first_err`/`mark_block_done` 直写无锁）；`next_block_for_parts(has_part)` per-part 位图过滤分发 + 源耗尽 nullopt 退出；完成信号 `asio::experimental::channel<void(boost::system::error_code,int)>`（leading ec 为 op-status、**禁 condition_variable** 防单 io_context 死锁）；setup 连接复用 spec §1.4。S4 多源 e2e：`serve_subset_peer`+`MultiSourceBothFull`+`MultiSourceAggregates`（A=part0/B=part1 互补聚合）+`MultiSourceSingleSubsetFails`（单源反证）。全套 224 绿 + 5 skip。**P4c-3 M1 验收通过**；M2/M3/M4 待 | 5187ff2 |
| 2026-07-03 | P4c-3 M2 完成（`.part.met` 续传接入，`0cf959a`）：`PartFile` met-first 续传——有效 `.part.met`（magic+hash+part_hashes 匹配）→ 按 gaps 恢复 `part_done_`/`block_done_` **无需重哈希**（D1 性能清偿）；缺失/损坏/陈旧 → 回退 `rehash_all`（P4a 安全网）。`write_block` part 完成时 `save_met()`。信任模型：met 标 done part 直接受信（仅 `file_size>=part_end` 防截断）。用户 scope 决策：`.part.met` 格式为内部 round-trip（非 aMule 字节级），跨客户端续传延后（非 v1.0 硬范围，D1 为性能目标）；格式隔离在 `parse/write_part_met` 可后续换 aMule-faithful。测试 +3（met-vs-rehash 分歧：trust/corrupt/stale）。全套 227 绿 + 5 skip。**P4c-3 M1+M2 验收通过**；M3/M4 待 | 0cf959a |
| 2026-07-03 | P4c-3 M3 完成（异步磁盘 I/O，`79ed544`）：`IoRuntime::disk_executor()`=`asio::thread_pool{1}`（单线程串行 `f_` 无须 strand）；`PartFile::write_block_async(start,end,data,disk_ex)` 严格状态/I/O 分离——网络线程改 `block_done_`/`part_done_` 状态、disk 线程做 `f_.seekp/write` 与 part 完成时 readback+MD4。**关键 Asio 细节**：`co_await post(ex, use_awaitable)` resume 于协程**关联** executor（网络线程）而非 `ex` → 无卸载；必须 `post(ex, bind_executor(ex, use_awaitable))` 强制 resume 于 `ex`，`DiskExecutorRunsOnSeparateThread` 锁定该陷阱（net_id≠disk_id）。`set_disk_executor` 注入 disk 池，默认=网络线程（同步等效，既有测试零破改）。`SharedState` 透传 `disk_ex`，`peer_worker` 写盘点改 `write_block_async`。测试 +2（`MultiSourceAsyncDiskOffload` 真实 disk 卸载 e2e + `DiskExecutorRunsOnSeparateThread` 线程 ID 结构断言）。全套 229 绿 + 5 skip。**P4c-3 M1+M2+M3 验收通过**；M4（live + >4GiB 边界）待 | 79ed544 |
| 2026-07-03 | P4c-3 M4 边界完成（>4GiB，`3275628`）：`Beyond4GiBBoundaryRoundTrip`——`file_size=4GiB+2*PART`（part 442 整个 >4GiB），仅下载 part 442（满 part 53 块，~9.7MB；PartFile 稀疏创建，预写 `.part.met` 全 gap 跳过 rehash_all 规避 444 part×9.7MB 冷启动开销）。验证 u64 偏移在 `BlockAllocator→encode_request_parts_i64→PartFile.seekp/write/readback/MD4` 全路径不发生 u32 窄化（D3 根因）：每块 `start>4GiB`、I64 wire round-trip 高位非零、part 满 MD4 通过 → `gaps()` 不含 part 442、磁盘逻辑大小 >4GiB。替代原 `RequestPartsI64RoundTrip` 占位 skip（i64 round-trip 在此真实执行）。全套 225 绿 + 4 skip（仅 live）。**P4c-3 M1+M2+M3+M4(边界) 验收通过**；M4 live 验证待（需用户真实 eMule 服务器=R0-1） | 3275628 |

---

## 附录 A：当前 CLI 能力（v0.1.0）

```
ed2k-tool hash <file> [--aich] [--red]                 # 算 ed2k 链接（P1）
ed2k-tool serverlist <server.met>                       # 解析 server.met（P1）
ed2k-tool parse <ed2k-link>                             # 解析 ed2k 链接（P1）
ed2k-tool login <server.met> [--ip:x.x.x.x] [--port:n]  # 登录服务器（P4c-1 M1）
ed2k-tool search <server.met> <keyword>                 # 关键词搜索（P4c-1 M1）
ed2k-tool sources <server.met> <ed2k-link>              # 取源（P4c-1 M1）
ed2k-tool download <ed2k-link> [--out:PATH] [--server:server.met]  # 下载（P4c-1 M2）
```

## 附录 B：关键协议参数速查

| 参数 | 值 |
|---|---|
| eD2k 块大小 | 9,728,000 字节（9500 KiB） |
| AICH 小块 | 184,320 字节（180 KiB），每 chunk 53 块 |
| 报文头 | 1B 协议(0xE3/0xC5/0xD4) + 4B 长度 + 1B opcode（小端） |
| 端口惯例 | C2C TCP 4662；全局服务器查询 UDP 4665；扩展 UDP 4672 |
| HighID 判定 | `id >= 0x1000000`（`!source.low_id()`） |
| 帧上限 | 8 MiB（`MAX_PACKET_SIZE`） |

## 附录 C：参考资料

- 设计文档：`docs/superpowers/specs/2026-06-26-ed2k-engine-design.md`（总体路线图）
- 各阶段 spec/plan：`docs/superpowers/specs/`、`docs/superpowers/plans/`
- 协议蓝本：aMule 源码（`opcodes.h`/`Client2Server/TCP.cpp`/`Client2Client/TCP.cpp`/`Packets.cpp`）、aMule Wiki `Ed2k_protocol`、Kulbak & Bickson eMule Protocol Spec、libed2k
