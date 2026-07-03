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
| **v1.0.0 MVP 下载器** | P4 收口（含 P4c-2/P4c-3）+ 发布工程 | P4c-2 AICH 互操作 + P4c-3 多源并发 + 真实服务器端到端下载（live 绿）+ README/打包/CI + 跨平台构建验证 | 🚧 差 P4c-2/P4c-3 + live 验证 + 发布工程 |
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
| **P4c-2 AICH 两级树互操作** | 真实 eMule AICH 两级树（OP_AICHFILEHASHREQ/ANS）+ `aich_hash_bytes` 回两级 + AICHChecker 两级 | ⬜ 未开始 |
| **P4c-3 多源并发 + 续传增强** | raccoon 多源并发 + 块粒度续传 + `peer::Block` u64 + 异步磁盘 I/O + .part.met 接入下载流程 | ⬜ 未开始 |

---

## 3. 当前状态快照（2026-07-03）

### 3.1 构建 & 测试

```
cmake --build build/default --config Debug --target ed2k_tests ed2k-tool  → 成功
./ed2k_tests.exe                                                          → 213 tests, 208 PASSED, 5 SKIPPED
```

跳过的 5 个测试：
- `Download.RequestPartsI64RoundTrip` — **预存 skip**（P3a 遗留，与本次发布无关，登记在案）
- `LiveServer.LoginReturnsId` / `SearchReturnsResults` / `GetSourcesReturnsOk` — **门控 live 测试**，`ED2K_LIVE` 未设故 skip
- `LiveDownload.HighIdSourceCompletes` — **门控 live 下载测试**，`ED2K_LIVE` 未设故 skip

> ⚠️ **关键风险**：4 个 live 测试**默认 skip，git 历史无「live 绿」提交记录**。P4c-1「真实互操作」在**代码层**已落地并 mock 回环全绿，但**从未在 CI/开发机上确认连真实 eMule 服务器跑绿**。这是 v1.0 发布前的**首要验证任务**（见 §5 R0）。

### 3.2 已实现能力清单

- **L0 基础原语**：MD4/SHA-1（自带实现，RFC1320/FIPS180 向量验证）、MD4Hash/AICHHash/IPv4、ByteReader/Writer（粘滞错误）、TLV Tag/TagList、ed2k 分块哈希（Red/Blue）、AICH SHA-1 Merkle、ed2k:// 链接解析、server.met/known.met/part.met 编解码 round-trip、错误码/spdlog
- **L1 网络核**：IoRuntime（单 io_context）、TCP 分帧（0xE3/0xC5/0xD4 + zlib inflate）、Connection（connect/send/recv/超时/取消）、UDP 分帧
- **L2 服务器协议**：ServerConnection（login/search/get_sources/callback/serverlist）、UDP 全局搜索/取源/stat/desc、SearchExpr 布尔树、服务器轮换+fallback
- **L3 下载引擎**：C2C 握手/hashset/filestatus/逐块下载、PartFile（part-MD4 校验+磁盘写+gap 续传+block bitmap）、BlockAllocator、AICHChecker（扁平 Merkle 块级损坏恢复）、MultiSourceDownload（**顺序单源**，非并发）、InboundListener（入站 C2C acceptor）、LowID 回调（OP_CALLBACKREQUEST + acceptor-mode 握手）
- **CLI**：`hash` / `serverlist` / `parse` / `login` / `search` / `sources` / `download`

### 3.3 已知技术债 / 未接线项

| # | 项 | 现状 | 归属 |
|---|---|---|---|
| D1 | `.part.met` / `known.met` API 存在但**未接入下载流程** | 续传靠重哈希数据文件（可用但慢） | P4c-3 |
| D2 | `MultiSourceDownload` **顺序单源**，非并发 | `download.cpp:189` 注释明示 raccoon 算法留后续 | P4c-3 |
| D3 | `peer::Block.start/end` 为 **u32**，限单块 ~4GiB | 与 u16 AICH 守卫 ~11.5GiB 不匹配 | P4c-3 |
| D4 | AICH 为**扁平单层** Merkle，与真实 eMule **两级树**不互操作 | M2 走 part-MD4 兜底，AICH 证明路径禁用 | P4c-2 |
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
6. **P4c-2 AICH 两级树互操作完成**：与真实 eMule peer 两级 AICH 互操作，`OP_AICHFILEHASHREQ/ANS` 路径启用（取代 part-MD4 兜底）。
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

- [~] **P4c-2-1 设计 spec**（🚧 子代理起草中，2026-07-03）：`docs/superpowers/specs/<date>-ed2k-p4c2-aich-interop-design.md`。对照 aMule `Client2Client/TCP.cpp` 锁定两级 AICH 树字节布局、proof 请求/应答帧。
- [ ] **P4c-2-2 实现计划**：TDD 任务分解。
- [ ] **P4c-2-3 `aich_hash_bytes` 回两级**：当前扁平单层 → 两级 Merkle（块根再组树）。
- [ ] **P4c-2-4 `AICHChecker` 两级校验**：`verify_block` 适配两级树。
- [ ] **P4c-2-5 `C2CConnection::request_aich_proof` 互操作**：真实 peer 的 `OP_AICHFILEHASHREQ/ANS` 往返。
- [ ] **P4c-2-6 `peer_worker` 启用 AICH 路径**：链接带 AICH root 时启用，而非强制 `aich=nullopt`。
- [ ] **P4c-2-7 测试**：mock 两级 AICH round-trip + live（若有支持 AICH 的真实源）。

### 阶段 P4c-3 — 多源并发 + 续传增强（v1.0 硬范围）

**依赖**：P4a/P4b（已完成）
**目标**：raccoon 多源并发下载 + 块粒度续传 + 大文件支持 + 异步磁盘。

- [~] **P4c-3-1 设计 spec**（🚧 子代理起草中，2026-07-03）：多源并发编排（跨 source 共享 BlockAllocator）、单线程 io_context 下并发模型（co_spawn 多 peer_worker + 共享状态，避免 condition_variable 死锁）。
- [ ] **P4c-3-2 实现计划**。
- [ ] **P4c-3-3 `peer::Block` u32→u64**：解除单块 ~4GiB 限制（D3）。
- [ ] **P4c-3-4 跨源共享 BlockAllocator**：多 peer_worker 并发取块、`mark_block_done` 线程安全（单网络线程→无锁）。
- [ ] **P4c-3-5 raccoon 调度**：`MultiSourceDownload::run` 改并发编排，替换顺序单源（`download.cpp:189`）。
- [ ] **P4c-3-6 `.part.met` 接入下载流程**：续传读 `.part.met` 而非重哈希数据文件（D1）。
- [ ] **P4c-3-7 异步磁盘 I/O**：磁盘写卸载到 worker 线程池（设计 §3 并发模型）。
- [ ] **P4c-3-8 测试**：多源并发 mock e2e + 续传 round-trip + 大文件（>4GiB）边界。

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
- [ ] P4c-2 AICH 两级树互操作完成（OP_AICHFILEHASHREQ/ANS + 两级 Merkle + peer_worker 启用 AICH）
- [ ] P4c-3 多源并发 + 续传增强完成（raccoon + Block u64 + .part.met 接入 + 异步磁盘）
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
| 2026-07-03 | /loop 启动：编排 v1.0 关键路径。R0-5 完成（CMake install/export + BUILD/INSTALL_INTERFACE 修复，configure/build/测试绿）。P4c-2-1/P4c-3-1 设计 spec 派子代理起草中 | 01f3928 |

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
