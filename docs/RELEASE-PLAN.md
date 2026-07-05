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
> **最近更新**：2026-07-05 — P5-8 SourceExchange 进展（本地提交 `5a1a052`）：`KnownFile` 增运行时 SX2 源列表，`UploadSession` 可返回非空 `ANSWERSOURCES2`；Windows 本地 285 测试 278 pass + 7 live skip。真实 aMule live 仍卡在 aMule `Total sources=0` 不回 SX2 / source-extended link 不入源列表。

---

## 1. 项目总览

| 项 | 内容 |
|---|---|
| 项目目标 | 用现代 C++ 从零实现跨平台 eDonkey2000/eMule (eD2k) 下载引擎，最终具备完整客户端能力（下载、上传分享、Kademlia、协议混淆），交付形态 = **可嵌入 C++ 库 + 示例 CLI** |
| 当前版本 | `1.0.0`（`src/util/version.cpp`） |
| 技术栈 | C++20、Boost.Asio 协程、`tl::expected<T,std::error_code>`（协议热路径无异常）、GoogleTest、zlib、spdlog、CMake + vcpkg manifest、MSVC/VS2022 |
| 交付形态 | 静态库 `ed2k_core` + CLI `ed2k-tool` |
| 协议保真准则 | 字节对照 aMule 源码锁定，协议保真优先于实现简化（`prefer-best-over-simplest`） |

### 1.1 发布目标分层（采用「分阶段发布」策略）

| 版本（建议） | 里程碑 | 完成定义 | 状态 |
|---|---|---|---|
| **v1.0.0 MVP 下载器** | P4 收口（含 P4c-2/P4c-3）+ 发布工程 | P4c-2 AICH 互操作 + P4c-3 多源并发 + 真实服务器端到端下载（live 绿）+ README/打包/CI + 跨平台构建验证 | ✅ 已发布（2026-07-04）：P4c-2 ✅ + P4c-3 ✅ + R0-1 live ✅ + R0-2 CI 双平台绿 ✅ + R0-3 跨平台构建验证 ✅ + R0-4 文档 ✅ + R0-5 版本 1.0.0 ✅ |
| **v1.1** | P5 上传/分享/信用 | 共享索引 + 服务器发布 + 上传会话 + 上传队列+限速 + 信用系统 + SourceExchange v2 + 评论/评分（spec/plan 已起草） | 🚧 进行中：M1/S1 ✅ + M2/S2-S4 上传/发布 ✅ + M3/S5-S7 上传队列/限速/信用 ✅ + M4/S8 SourceExchange/评论基线 ✅（[spec](superpowers/specs/2026-07-04-ed2k-p5-upload-sharing-credits-design.md)/[plan](superpowers/plans/2026-07-04-ed2k-p5-upload-sharing-credits-impl-plan.md)） |
| **v1.2** | P6 KAD | Kad 路由表 + bootstrap + Kad2 UDP + 搜索/取源/发布 + buddies + notes（spec/plan 已起草） | ⬜ 未开始（[spec](superpowers/specs/2026-07-04-ed2k-p6-kad-design.md)/[plan](superpowers/plans/2026-07-04-ed2k-p6-kad-impl-plan.md)） |
| **v2.0** | P7 协议混淆 | MD5/RC4 + TCP/UDP/服务器混淆 + 握手协商 + fallback（spec/plan 已起草） | ⬜ 未开始（[spec](superpowers/specs/2026-07-04-ed2k-p7-obfuscation-design.md)/[plan](superpowers/plans/2026-07-04-ed2k-p7-obfuscation-impl-plan.md)） |
| **v2.1** | P8 客户端基础设施 | IPFilter + Preferences + Statistics + Category + FriendList + ClientList + Proxy + HTTPThread + .emulecollection + preview + scheduler + **ChatRelay（OP_MESSAGE 中继）**（spec/plan 已起草） | ⬜ 未开始（[spec](superpowers/specs/2026-07-04-ed2k-p8-client-infra-design.md)/[plan](superpowers/plans/2026-07-04-ed2k-p8-client-infra-impl-plan.md)） |
| **v2.2** | P9 eD2k 协议完备性 | 服务器 UDP 完备 + 服务器列表交换 + MuleInfo + AICH 共享端 + 压缩块上传 + aMule-faithful .part.met（跨客户端续传）+ 大文件边界（spec/plan 已起草） | ⬜ 未开始（[spec](superpowers/specs/2026-07-04-ed2k-p9-protocol-completeness-design.md)/[plan](superpowers/plans/2026-07-04-ed2k-p9-protocol-completeness-impl-plan.md)） |

> **为何分阶段**：v1.0 已发布可用下载器；v1.1-v2.2 增量补齐 aMule 全功能对等（除 UI）。**v2.2 完成定义**：P5+P6+P7+P8+P9 全完成 = 引擎达到 aMule 协议级全功能对等，交付形态 = 可嵌入 C++ 库 + CLI，完整 eD2k 客户端能力。
>
> **v1.0 范围决策（用户 2026-07-03 确认）**：P4c 全部工作（P4c-2 AICH 互操作 + P4c-3 多源并发）**必须在 v1.0 前完成**，与 R0 发布工程同属 v1.0 硬范围——详见 §4。
>
> **v1.1-v2.2 范围决策（用户 2026-07-04 确认）**：对标 eDonkey2000/eMule 全部引擎功能（除 UI），P5-P9 五阶段 spec/plan 全部起草冻结。

---

## 2. 路线图总览（P1–P7）

| 阶段 | 内容 | 里程碑 | 状态 | 证据 |
|---|---|---|---|---|
| **P1 地基** | L0：crypto/core/codec/hash/link/metfile/util + CLI hash/serverlist/parse | 纯本地单测全覆盖 | ✅ 已完成 | `215f37f` 起；`md4/sha1/ed2k_hasher/aich_hasher/server_met/known_part_met/tag/byte_io/link` 全套测试 |
| **P2 网络核** | L1：Asio 协程运行时、TCP 分帧收发、超时/取消、zlib inflate | 与 mock 回环测试 | ✅ 已完成 | `f303c7d` 设计；`net/{runtime,framing,connection,packet,inflate,udp_*}` |
| **P3 服务器协议** | L2：TCP 登录/HighID-LowID/搜索/取源/回调 + UDP 全局搜索/取源 | 首次上线连服务器搜文件拿源（mock） | ✅ 已完成 | P3a `d1e8c37` + P3b `57c9ced`；`server/{connection,messages,search_query,udp_*}` |
| **P4 下载引擎** | L3：C2C 握手、hashset 交换、块下载、part-MD4 校验、AICH 恢复、多源调度、断点续传 | ⭐ 首次端到端下载完整文件（MVP） | 🚧 部分完成 | 见 §3 |
| **P5 上传/分享/信用** | L4：共享索引(known.met/known2.met)、OP_OFFERFILES 发布、上传会话、上传队列+限速、ClientCredits、SourceExchange v2、评论/评分 | 有来有往的节点 | 🚧 进行中 | M1/S1 ✅；M2/S2-S4 ✅；M3/S5-S7 ✅；M4/S8 ✅；P5-8 live 待办 |
| **P6 KAD** | L5：Kad2 路由表(k-bucket)、bootstrap(nodes.dat)、Kad2 UDP、搜索/取源/发布、buddies、notes | 无服务器找源下载 | ⬜ 未开始 | spec/plan 已起草 |
| **P7 混淆加密** | L6：MD5/RC4 自带、TCP/UDP/服务器混淆、握手协商+fallback | 兼容开启 obfuscation 的网络 | ⬜ 未开始 | spec/plan 已起草 |
| **P8 客户端基础设施** | L7：IPFilter、Preferences、Statistics、Category、FriendList、ClientList、Proxy、HTTPThread、.emulecollection、preview、scheduler、ChatRelay | 完整客户端管理能力 | ⬜ 未开始 | spec/plan 已起草 |
| **P9 eD2k 协议完备** | L8：服务器 UDP 完备、服务器列表交换、MuleInfo、AICH 共享端、压缩块上传、aMule-faithful .part.met、大文件边界 | aMule 协议级全功能对等 | ⬜ 未开始 | spec/plan 已起草 |

### P4 子阶段明细

| 子阶段 | 内容 | 状态 |
|---|---|---|
| P4a 下载引擎 | 单源 Download 编排 + PartFile part-MD4 校验 + 磁盘写 + gap 续传 + 块级多源（8MiB 帧限） | ✅ 已完成 |
| P4b 下载增强 | BlockAllocator + AICHChecker Merkle 校验 + MultiSourceDownload 骨架 | ✅ 已完成 |
| P4b AICH 恢复 | 扁平 AICH 块级损坏恢复（184320B 块）+ 同源重试 + e2e/单源测试 | ✅ 已完成 |
| **P4c-1 真实互操作** | `ed2k-tool` login/search/sources/download + server_session 编排 + LowID 回调框架（InboundListener + OP_CALLBACKREQUEST + peer_worker 分支）+ 门控 live 测试 | ✅ 已完成（代码） |
| **P4c-2 AICH 两级树互操作** | 真实 eMule AICH 两级树（OP_AICHFILEHASHREQ/ANS）+ `aich_hash_bytes` 回两级 + AICHChecker 两级 | ✅ M1✅ M2✅ M3✅ M4✅（opcode 已对 aMule 确认） |
| **P4c-3 多源并发 + 续传增强** | raccoon 多源并发 + 块粒度续传 + `peer::Block` u64 + 异步磁盘 I/O + .part.met 接入下载流程 | ✅ M1✅ M2✅ M3✅ M4✅（raccoon 并发骨架+多源 e2e+.part.met 续传+异步磁盘卸载+>4GiB 边界+**M4 live vs 本地 aMule 2.3.3 peer 单/多 part MD4 校验通过**） |

---

## 3. 当前状态快照（2026-07-03）

### 3.1 构建 & 测试

```
cmake --build build/default --config Debug --target ed2k_tests ed2k-tool  → 成功
./ed2k_tests.exe                                                          → 234 tests, 229 PASSED, 5 SKIPPED (live 门控)
```

> 全套 mock 回环 229+ 绿 + live skip（默认无 `ED2K_LIVE`）。当前 7 个 live 测试 = 3 `LiveServer.*` + `LiveDownload.HighIdSourceCompletes` + `LiveDownload.LocalPeerCompletes` + 2 `LiveUpload.*`。**既有 live 实测**：3 `LiveServer.*` 绿（vs 45.82.80.155:5687，`4268716`）；`LocalPeerCompletes` 绿（vs 本地 aMule 2.3.3 peer，单 part 5.57MB + 多 part 29MB 全程 MD4 校验通过，见 §5 R0-1）。`HighIdSourceCompletes` 仍环境受阻（公网源冷连被拒，非代码缺陷），已被 `LocalPeerCompletes`（直连可靠本地 peer）覆盖取代。P5 `LiveUpload.*` harness 已加入，真实 aMule upload/source-exchange live 仍待执行。

跳过的 7 个测试（均 live 门控，默认 skip）：
- `LiveServer.LoginReturnsId` / `SearchReturnsResults` / `GetSourcesReturnsOk` — **门控 live 测试**，设 `ED2K_LIVE` 后绿
- `LiveDownload.HighIdSourceCompletes` — **门控 live 下载测试**，公网源受阻（见 R0-1）
- `LiveDownload.LocalPeerCompletes` — **门控 live 下载测试**，设 `ED2K_LIVE + ED2K_LINK + ED2K_SOURCE` 后绿（vs 本地 aMule peer）
- `LiveUpload.SourceExchange2WithLocalPeer` — **门控 P5 live 源交换测试**，设 `ED2K_LIVE + ED2K_LINK + ED2K_SOURCE` 后向本地 aMule peer 请求 SX2。
- `LiveUpload.AcceptsLocalPeerUploadSession` — **门控 P5 live 上传测试 harness**，设 `ED2K_LIVE + ED2K_UPLOAD_FILE [+ ED2K_UPLOAD_PORT]` 后监听真实 peer 请求。

> ✅ **R0-1 live 验证已达成**：3 服务器 live + `LocalPeerCompletes` 直连本地 aMule 2.3.3 peer 下载完整文件 MD4 校验通过 = 4 live 测试绿。P4c-1「真实互操作」在代码层 + 真实 peer 双重确认。`HighIdSourceCompletes` 的公网源穷举受阻（12/12 公网 HighID 源握手失败，协议交换前关闭）由 `LocalPeerCompletes`（用户指定的「可靠源」= 本地 aMule 实例）取代——后者更直接地验证完整 P2P 下载路径（raccoon 多源 + AICH + per-part MD4）。

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
| D6 | ~~live 测试**从未确认绿**~~ | ✅ 已修复：3 `LiveServer.*` + `LocalPeerCompletes`（本地 aMule 2.3.3 peer，单/多 part MD4 校验通过）= 4 live 绿 | R0 ✅ |
| D7 | **无 CI** | 无 `.github/workflows` | R0 |
| D8 | **无 README / 用户文档 / 安装说明** | 仅 design spec/plan | R0 |
| D9 | **仅 Windows/MSVC 验证** | 设计目标含 Linux/macOS | R0 |
| D10 | **无打包/安装产物** | 无 `install()` / vcpkg port / 二进制发布 | R0 |
| D11 | `encode_callback_request` 等曾为死代码 | P4c-1 已接线，需确认无残留死代码 | 收尾核查 |

---

## 4. 距离发布的差距分析

### 4.1 v1.0 MVP 下载器 — 完成定义（DoD）

v1.0 = **真实可用、可分发**的 eD2k 下载器。必须满足：

1. **真实互操作 live 验证绿**：`ED2K_LIVE=1` 下，`LiveServer.*` 三条 + `LiveDownload.LocalPeerCompletes`（直连本地 aMule 2.3.3 peer，单 part 5.57MB + 多 part 29MB 全程 MD4 校验通过）跑通。`HighIdSourceCompletes`（公网源）穷举受阻但被 `LocalPeerCompletes` 取代覆盖。（D6 ✅）
2. **跨平台构建**：Windows(MSVC) + Linux(GCC/Clang) 至少双平台 CMake+vcpkg 干净构建、测试全绿。（D9）
3. **CI**：PR/push 触发构建+测试（mock 回环必跑，live 门控手动）。（D7）
4. **用户文档**：README（简介/构建/用法/限制）、CLI 用法、公共 API 概览。（D8）
5. **打包**：CMake `install()` 目标 + 版本号升 `1.0.0`。（D10）
6. **P4c-2 AICH 两级树互操作完成**：与真实 eMule peer 两级 AICH 互操作，`OP_AICHFILEHASHREQ/ANS` 路径启用（取代 part-MD4 兜底）。✅ 完成（mock e2e 绿；live 真实 AICH 源留 R0-1）
7. **P4c-3 多源并发 + 续传增强完成**：raccoon 多源并发、`peer::Block` u64、`.part.met` 接入续传、异步磁盘 I/O。✅ 完成（含 M4 live：`LocalPeerCompletes` vs 本地 aMule 2.3.3 peer 单/多 part MD4 校验通过）
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

- [x] **R0-1 live 真实互操作验证**【v1.0 首要】（4/4 绿：3 LiveServer + LocalPeerCompletes，`4268716` + 本次 live 下载修复）
  - 设 `ED2K_LIVE=1 ED2K_SERVER=<可达服务器> ED2K_LINK=<测试链接> ED2K_EXPECT_MD4=<期望>` 跑 live 测试。
  - 8 个内建 fallback 服务器（见 P4c-1 spec §6.5）：45.82.80.155:5687 等。
  - ✅ LoginReturnsId / SearchReturnsResults / GetSourcesReturnsOk 绿（vs 45.82.80.155:5687）。
  - ✅ live 暴露并修复两处协议保真缺陷（tag 类型 + STR1-STR16 + IP 字节序，见 changelog `4268716`）——R0-1 反向触发协议 hotfix 验证 spec §7 风险点。
  - ✅ **LocalPeerCompletes 绿**（vs 本地 aMule 2.3.3 peer，WSL2 amuled 端口 4662）：单 part 5.57MB（`ed2k_live_test.bin`，hash `101f7523…b878`）+ 多 part 29MB（`ed2k_live_multi.bin`，3 part 恰为 PART_SIZE 整数倍，Red 变体空尾 part，hash `262a4f329acf61426f6491d80205037b`）全程 MD4 校验通过（多 part live 跑 ~566s，per-op 300s 超时未触发）。用户指定「自己联网找可靠源、不要图方便简短实现」→ 自建本地 aMule 实例作可靠 HighID 源，绕过公网冷连被拒。**真实 peer 暴露并修复 7 处协议保真缺陷**（逐字节对照 aMule 2.3.3 源码）：① `request_blocks` 多子帧累积——aMule `CreateStandardPackets` 把每个请求区间切 ~10240B 子帧（184320B 区间 → 18 帧），原 `while(blocks.size()<3)` 假设「一区间一帧」致仅下 931840B（5×184320+10240）；改为 `accumulate_blocks` per-range 缓冲按字节偏移累积至连续覆盖。② 单 part 文件跳过 `request_hashset`——aMule `GetHashCount()==0` 时 `SendHashsetPacket` 静默不应答（`UploadClient.cpp` 守卫），原请求挂起；改 `size<=PART_SIZE` 跳过、PartFile 自合成 `{file_hash}`。③ HELLO/HELLOANSWER 不对称——HELLO 前导 `0x10` hashsize 字节、HELLOANSWER 无前导（`BaseClient.cpp SendHelloPacket` vs `SendHelloAnswer`），原二者复用同一编解码致 acceptor 路径解析错位；拆 `encode_hello_packet`（加 0x10）/`decode_hello`（校验并跳过 0x10）。④ HELLO body 尾部 `server_ip:4 BE`+`server_port:2`——`SendHelloTypePacket` 末尾无条件写入（0/0 若未连服务器），原编码漏写致 aMule `ProcessHelloPacket` 读 tag 越界。⑤ HASHSETANSWER 前导 `file_hash:16`——`SendHashsetPacket` 线序 `[file_hash][count][part_hashes]`，`ProcessHashsetAnswer` 先读 file_hash 校验 == 请求 hash 不符即丢弃；原解码直接读 count 漏前 16 字节，`decode_hashset_answer` 改取 `expected` 校验。⑥ ed2k 文件哈希 Red 变体——aMule 对 PART_SIZE 整数倍文件追加空尾 part MD4("")=`31d6cfe0…089c0`（`SHAHashSet`），文件 hash = MD4(part_hashes 含空尾)；`hash_bytes/hash_file` 默认 Blue→Red，live 校验改 Red。⑦ **FILESTATUS count=0 = 完整文件**——aMule `ClientTCPSocket.cpp OP_SETREQFILEID` 处理 `if(reqfile->IsPartFile()) WritePartStatus else WriteUInt16(0)`：完整共享文件发 `[hash:16][count=0]`（无位图）= 拥有整文件所有 part，**非「0 part」**；原引擎视空位图为「无 part 可用」致 `missing_parts_peer_has` 返回空 → 多 part 下载 0 字节。`download.cpp` 两处（单源 `run` + 多源 `peer_worker`）空 `fs->parts` 时 `assign(num_parts, true)` 视为全部可服务。同步：`PartFile::num_parts` 取 `ceil(size/PART_SIZE)` 而非 hash 计数（Red 空尾 part 不占数据 part 槽，`part_done_`/`block_done_` 按数据 part 数分配，`rehash_all`/`write_block` 越界守卫 `p < part_hashes_.size()`）；移除 6 处 mock 的 per-batch `OP_OUTOFPARTREQS`（aMule 不逐批发，仅上传槽回收时发；per-batch 发致多块下载残留帧 → 下一轮 `request_blocks` 误断）。新增 4 单测（`EncodeHelloPacket`/`DecodeHello`/`DecodeHelloRejectsBadHashsize`/`DecodeHashsetAnswerHashMismatch`）。
  - ⚠️ HighIdSourceCompletes 环境受阻（非代码缺陷，穷举确认；**已被 LocalPeerCompletes 取代覆盖**）：12 个公网 HighID 源探针 12/12 失败（8 connection_closed + 4 connect_failed），0 个回 HELLOANSWER——2026 公网 eMule 源对未知 IP 冷直连一律协议交换前关闭。framing/HELLO 已对照 aMule 且与 live 服务器登录同路径（绿）。下载路径本身由 `LocalPeerCompletes`（真实 aMule peer）+ 228 mock e2e 锁定。
  - 失败则按 aMule 源码逐字节排查登录/hashset/blocks 帧（P4c-1 spec §3.5/§4.6 风险点清单）。
  - 产出：live 绿记录写入 §9 + 测试链接固化到文档（非代码硬编码）。
- [x] **R0-2 CI 流水线**（✅ 2026-07-04 双平台绿，run `28695894770`）
  - `.github/workflows/build.yml`：Windows(MSVC, preset `default`)+Ubuntu(GCC, preset `linux`/Ninja) 矩阵，vcpkg manifest 安装，`cmake --preset` + `cmake --build --preset` + `ctest`。live 测试默认 skip（无 `ED2K_LIVE`）。
  - **vcpkg versioning 修正（2026-07-04）**：manifest mode 的 `builtin-baseline` 要求本机 vcpkg 为**完整（非 shallow）clone 且 HEAD ≥ baseline commit**——否则版本数据库缺 baseline 引用的条目（实测旧 vcpkg 报 `no version database entry for boost-asio@1.91.0`）。workflow 新增「Set up vcpkg」步：用 runner 预装 vcpkg（`VCPKG_INSTALLATION_ROOT`，完整 clone）或回退 fresh full clone → `git fetch --tags` → `git checkout <baseline>` → `bootstrap-vcpkg`；并用 `VCPKG_BINARY_SOURCES=clear;x-gha,readwrite` + `actions/github-script` 导出 `ACTIONS_CACHE_URL`/`ACTIONS_RUNTIME_TOKEN` 启用 GitHub Actions 缓存（编译依赖跨 run 复用）。baseline 从 `vcpkg.json` 动态读取（`grep+sed` 提取 40-hex），无硬编码。
  - **目标仓库**：`cool2528/ed2k-engine-cpp`（public，2026-07-04 已推送，`main` @ `cfcbff6`）。git remote `origin` 已配置（SSH）。用户 /loop 授权：可用本机 gh 在 GitHub 操作、自主决策至发布就绪。
  - ⚠️ 首次 push 触发 CI 双平台运行；失败则在仓内修 preset/可移植性。本地 Windows + WSL Linux 构建先于 push 验证（见 R0-3）。
- [x] **R0-3 跨平台构建验证**（✅ 2026-07-04 CI 双平台绿 + 本地 Windows 绿）
  - 静态扫描：库/CLI 代码**无** Winsock 头 / `_WIN32`/`_MSC_VER` / Windows API（`Sleep`/`SOCKET`/`WSAStartup`）/反斜杠路径——全经 Boost.Asio 抽象；`_WIN32_WINNT=0x0A00` 已 `$<PLATFORM_ID:Windows>` 守卫（Linux 不定义）。CMake 用 `find_package`/`GNUInstallDirs`/`Threads` 全跨平台。
  - `linux` preset（Ninja 单配置 + `CMAKE_BUILD_TYPE=Debug`）已就位。
  - **✅ vcpkg baseline 修复（2026-07-04）**：原 `builtin-baseline: 15e5f3820f…` 在上游已不可达（rebase/移除），Windows 本机 vcpkg（HEAD `89dc8be6db` / 2025-05-31）cat-file 亦报不存在。**修复**：baseline 更新为上游稳定 tag `2026.06.24` 的 commit `cd61e1e26a038e82d6550a3ebbe0fbbfe7da78e3`——gtest 1.17.0（≥1.14.0 ✅）、boost-asio 1.91.0 等均在版本数据库。同时发现 vcpkg manifest versioning 要求**本机 vcpkg HEAD ≥ baseline commit 且为完整 clone**（shallow clone 缺历史 port tree 对象，报 `failed to unpack tree object`）：
    - **Windows 本机 vcpkg**（`D:\tools\vcpkg`）：`git checkout cd61e1e26a` + `bootstrap-vcpkg.sh`（HEAD = baseline，版本数据库匹配）。
    - **WSL vcpkg**（`/opt/vcpkg`）：`git clone --branch 2026.06.24 --depth 1` 后 `git fetch --unshallow`（补全历史 port tree 对象）。
    - **CI**（`.github/workflows/build.yml`）：runner 预装 vcpkg（完整 clone）`git checkout <baseline>` + `bootstrap-vcpkg.sh`；baseline 从 `vcpkg.json` 动态读取（见 R0-2）。
  - **本地 WSL 验证进度（2026-07-04，Ubuntu-24.04）**：工具链 `g++ 13.3.0` / `cmake 3.28.3` / `ninja 1.11.1`；vcpkg@`/opt/vcpkg`（baseline commit + 完整历史）；源码从 `/mnt/d/workspace/ed2k-engine-cpp` rsync 到 `/root/ed2kengine`（原生 fs，排除 `build/`/`vcpkg_installed/`/`.git`）。configure + build + test 进行中。
  - **本地 Windows 验证 ✅（2026-07-04）**：`cmake --preset default` + `cmake --build build/default --config Debug --target ed2k_tests ed2k-tool` + `ctest -C Debug -j 8` → **234 测试 229 passed + 5 skipped（live 门控）0 failed**（23.10s）。vcpkg install 6.9min（boost-asio 1.91.0 等从源码编译）。baseline 修复在 Windows 确认有效。
  - **本地 WSL Linux 验证 ✅（2026-07-04）**：vcpkg install 49min（Boost 子包逐个下载，WSL2 网络/IO 慢）+ configure + build + `ctest --preset linux` → **234 测试 229 pass + 5 live skip，0 fail**（22.32s）。源码同步至 `0a7356c`（含测试修复 + 版本 1.0.0）。本地 Linux 确认达成（与 CI ubuntu-latest 双重验证）。
  - 目标：双平台 `ed2k_tests` 全绿（229 pass + 5 live skip）。✅ 达成（CI 双平台 + 本地 Windows + 本地 WSL Linux，四重确认）。
- [x] **R0-4 README + 用户文档**（✅ 2026-07-03）：`README.md`（项目简介/协议覆盖/构建 vcpkg+CMake/CLI 用法/架构 single-io_context+raccoon+异步磁盘/Asio gotcha/关键参数/live 测试门）、`docs/USAGE.md`（7 个 CLI 子命令详解 + 示例 + 退出码 + .part.met 续传行为）、`docs/API.md`（公共 API 按 net/hash/core/link/metfile/server/download/app 模块概览 + 并发契约）、`CHANGELOG.md`（Keep a Changelog 格式，P4c-1/2/3 + 0.1.0）。**2026-07-04 push-readiness 刷新**（`4ea5bc0`）：补 `LICENSE`（MIT，Copyright 2026 cool2528）；README H1→`ed2k-engine-cpp`（对齐 GitHub 仓）、状态表 live ⏳→✅ + 测试数 225/4→229/5、补 Linux（`linux` preset）构建段、重写 Live tests 段（R0-1 绿/`ED2K_SOURCE`/本地 aMule peer/7 保真修复）、补 aMule Acknowledgements；源码无 license header（仓级 LICENSE 已足够，SPDX header 可选后续补）。
- [x] **R0-5 打包与版本**（install/export ✅ 2026-07-03；版本号升 1.0.0 ✅ 2026-07-04）
  - [x] `CMakeLists.txt` `install(TARGETS ed2k_core ed2k-tool EXPORT ed2kTargets)` + 公共头安装 + `ed2k::` 目标导出 + `BUILD_INTERFACE/INSTALL_INTERFACE` include 修复。
  - [x] `version.cpp` 升 `1.0.0`；`project(VERSION 1.0.0)`、`vcpkg.json` version、`README.md`、`CHANGELOG.md` 同步。
  - [ ] （可选）vcpkg port / Release 二进制。
- [x] **R0-6 死代码/收尾核查**（✅ 2026-07-03）
  - D11 确认：`encode_callback_request` 全链接线——`messages.cpp`→`ServerConnection::callback_request`（`connection.cpp:89`）→`download.cpp:101/181` peer_worker LowID 回调分支 + `CALLBACKREQUESTED` 解码（`connection.cpp:23`）。commits `d6184d2`/`9aea1ee`/`eefa694` 已落地。
  - `RequestPartsI64RoundTrip` 占位 skip → 替换为 `Beyond4GiBBoundaryRoundTrip`（真实 >4GiB 边界 + i64 round-trip，绿）。skip 项现为 4 个 live（已登记 §3.1）。
  - 死代码扫描：`filter_high_id`/`fallback_servers`/`build_targets` 均有引用（impl+test）；`udp_*` 模块为**已测但未接线**（独立技术债，非死代码，移除将丢覆盖）；`encode_get_server_list` 为已登记 stub。无可安全移除的真死代码。

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
- [x] **P4c-3-8 测试（剩余）**：M4 live 验证 ✅（`LocalPeerCompletes` vs 本地 aMule 2.3.3 peer，单 part 5.57MB + 多 part 29MB 全程 MD4 校验通过，R0-1）。

> **P4c-3 M1+M2+M3+M4 验收 ✅**（2026-07-03）：raccoon 多源并发骨架（S1–S4）+ `.part.met` 续传接入 + 异步磁盘 I/O 卸载 + >4GiB 边界 + **M4 live（LocalPeerCompletes vs 本地 aMule 2.3.3 peer 单/多 part MD4 校验通过）**全绿。**P4c-3 全部 v1.0 硬范围完成。**

### 阶段 P5 — 上传/分享/信用系统（v1.1）

**依赖**：v1.0（含 InboundListener，P4c-1 M3 已铺路）
**目标**：共享索引、向服务器发布、上传队列 + 信用系统、SourceExchange v2、评论/评分。
**设计/实现**：[spec](superpowers/specs/2026-07-04-ed2k-p5-upload-sharing-credits-design.md) / [plan](superpowers/plans/2026-07-04-ed2k-p5-upload-sharing-credits-impl-plan.md)

- [x] **P5-1 设计 spec**（✅ 已起草 2026-07-04）：L4 架构 + 逐帧字节级 + M1-M4 里程碑 + G1-G8 陷阱。
- [x] **P5-2 实现计划**（✅ 已起草 2026-07-04）：S1-S8 green-deployable + 测试门 + 破改分析。
- [x] **P5-3 共享索引 + known.met/known2.met**（M1/S1）：`KnownFileDB` + `known.met`/`known2.met` round-trip + 扫目录建索引 + PartFile→KnownFile 迁移（`499b722`，239/234/5 不回归）。
- [x] **P5-4 服务器发布 OP_OFFERFILES**（M2/S2）：`publish_files` + tag 顺序/类型（G4）+ CLI `publish`（`45d72e7`，242/237/5 不回归）。
- [x] **P5-5 上传会话**（M2/S3-S4）：`UploadSession` 响应 FILEREQ/FILESTATUS/HASHSET/REQUESTPARTS/AICH*（下载端协议的服务端镜像，对称复用）+ 读盘卸载（S3 `a5ca1db` + S4 `c3f3e7d`，255/250/5 不回归）。
- [x] **P5-6 上传队列 + 限速 + 信用**（M3/S5-S7）：`UploadQueue` + slot 调度 + `UploadBandwidthThrottler` token bucket + `ClientCredits`(clients.met) + 信用分影响 slot。S5 上传队列/slot 调度 ✅（`350a100`，264/259/5 不回归）；S6 非阻塞限速 ✅（`a02e6e8`，267/262/5 不回归）；S7 信用 ✅（`c120c20`，271/266/5 不回归）。
- [x] **P5-7 SourceExchange v2 + 评论/评分**（M4/S8）：`OP_ASKSHAREDFILES`/`OP_ASKSHAREDFILESANSWER` + SX2 `OP_REQUESTSOURCES2`/`OP_ANSWERSOURCES2` + `OP_FILEDESC` mock/编码基线完成；live 对 aMule peer 留 P5-8。
- [ ] **P5-8 测试 + live**：mock 上传回环 + live（本地 aMule peer 互传源/上传）。进展：`1e79125` 已补评论/评分同步、`comment` CLI、P5 live harness；本地追加 SX2 live 调试：`LiveUpload.SourceExchange2WithLocalPeer` 先发 `SETREQFILEID` 锁定请求文件，`UploadSession` 对 `OP_REQUESTSOURCES2` 兼容 hash-only 与 `version/options/hash` 两种 payload；对 WSL aMule 2.3.3 实测，hash-only standalone 请求保持连接但因 aMule 当前 `Clients in queue=0`/`Total sources=0` 无 `ANSWERSOURCES2` 返回而超时，19B standalone 请求会被 aMule 2.3.3 接收端断开（其独立 opcode 路径仍检查 `size == 16`）。本地提交 `5a1a052` 进一步补齐运行时 SX2 源列表：`KnownFile::sources` 持有已知 `PeerSource`，`UploadSession` 对 `REQUESTSOURCES2` 返回非空 `ANSWERSOURCES2`，新增 `UploadSession.AnswersRequestSources2WithKnownSources`；Windows 全套 285 测试 278 pass + 7 live skip。2026-07-05 WSL aMule 2.3.3 live 再测：启动 amuled（4662/4672，EC 4712），共享 `ed2k_p5_live_source.bin` 并确认 1 known shared file；本节点 `publish` 同 hash 成功；`LiveUpload.SourceExchange2WithLocalPeer` 仍因 aMule `Total sources=0` 超时。尝试 `ed2k://...|/|sources,172.22.32.1:4663|/` 触发 aMule 拉本节点上传，aMule 接受 link 但下载仍 `0/0 Waiting`、`Total sources=0`，未连接 harness。真实 aMule live 互传源仍待构造 aMule 可接受的第二 source/source-list 后完成。

### 阶段 P6 — KAD（v1.2）

**依赖**：v1.0 UDP framing；P5 可选
**目标**：无服务器找源下载。
**设计/实现**：[spec](superpowers/specs/2026-07-04-ed2k-p6-kad-design.md) / [plan](superpowers/plans/2026-07-04-ed2k-p6-kad-impl-plan.md)

- [ ] **P6-1 设计 spec**（✅ 已起草）：Kad2 128-bit + 路由表 + Kad2 UDP 帧字节级 + M1-M4 + G1-G9。
- [ ] **P6-2 实现计划**（✅ 已起草）：S1-S7 + 测试门 + 破改分析。
- [ ] **P6-3 KadID + 路由表 + nodes.dat**（M1/S1）：128-bit KadID + k-bucket(k=10) + RoutingZone 二叉 trie + 最近 k 查找。
- [ ] **P6-4 Kad2 UDP + Hello + bootstrap**（M2/S2-S3）：HELLO/REQ/RES + verify key + bootstrap 收敛。
- [ ] **P6-5 搜索/取源/发布**（M3-M4/S4-S5）：关键词/文件/源搜索 + PUBLISH + KadIndexed(TTL) + 迭代收敛。
- [ ] **P6-6 Firewalled + buddies**（M4/S6）：firewall 检测 + buddy 中转 + LowID Kad callback。
- [ ] **P6-7 集成 + CLI + live**（S7）：MultiSourceDownload 接 Kad 找源 + CLI `kad-*` + live bootstrap。

### 阶段 P7 — 协议混淆/加密（v2.0）

**依赖**：v1.0 + P2/P3/P4 稳定；与 P5/P6 正交
**目标**：兼容开启 obfuscation 的网络。
**设计/实现**：[spec](superpowers/specs/2026-07-04-ed2k-p7-obfuscation-design.md) / [plan](superpowers/plans/2026-07-04-ed2k-p7-obfuscation-impl-plan.md)

- [ ] **P7-1 设计 spec**（✅ 已起草）：MD5/RC4 + TCP/UDP/服务器混淆握手字节级 + M1-M4 + G1-G8。
- [ ] **P7-2 实现计划**（✅ 已起草）：S1-S6 + 测试门 + 破改分析。
- [ ] **P7-3 MD5/RC4 自带实现**（M1/S1）：RFC1321 + RC4 KSA/PRGA + keystream 续接。
- [ ] **P7-4 TCP 混淆握手 + 帧加密**（M2/S2-S3）：`EncryptedStreamSocket` + 随机前导识别 + key 派生 + 透明加解密。
- [ ] **P7-5 UDP + 服务器混淆 + 协商 fallback**（M3-M4/S4-S6）：`ObfuscatedUdpSocket` + 服务器 obfuscation 端口 + 探测 fallback plain + live。

### 阶段 P8 — 客户端基础设施（v2.1）

**依赖**：v1.0 + P5（Statistics/ClientList 协同）
**目标**：补齐 eMule 引擎级基础设施（除 UI）。
**设计/实现**：[spec](superpowers/specs/2026-07-04-ed2k-p8-client-infra-design.md) / [plan](superpowers/plans/2026-07-04-ed2k-p8-client-infra-impl-plan.md)

- [ ] **P8-1 设计 spec**（✅ 已起草）：IPFilter/Preferences/Statistics/Category/FriendList/ClientList/Proxy/HTTPThread/collection/preview/scheduler + M1-M5 + G1-G9。
- [ ] **P8-2 实现计划**（✅ 已起草）：S1-S8 + 测试门 + 破改分析。
- [ ] **P8-3 IPFilter**（M1/S1）：`ipfilter.dat` 解析 + interval tree + 连接前过滤 + level 阈值。
- [ ] **P8-4 Preferences + Statistics**（M2-M3/S2-S3）：引擎配置 ~50 项 round-trip + session/cumulative 计数 + 异步持久化。
- [ ] **P8-5 Category + FriendList + ClientList**（M4/S4-S5）：分类归档 + friend slot 优先 + ClientList LRU。
- [ ] **P8-6 Proxy + HTTPThread + collection + preview + scheduler + ChatRelay**（M5/S6-S7）：SOCKS5/HTTP 代理 + HTTP 自动更新 + .emulecollection + OP_PREVIEWREQ/ANS + cron 调度器 + **聊天消息中继（`OP_MESSAGE` server-relayed + C2C，与 HTTPThread 同级）**。
- [ ] **P8-7 集成 + CLI + live**（S8）：统一 CLI + 启动流程 + live IPFilter/更新/代理/chat。

### 阶段 P9 — eD2k 协议完备性（v2.2）

**依赖**：v1.0 + P5 + P8
**目标**：aMule 协议级全功能对等（除 UI）。
**设计/实现**：[spec](superpowers/specs/2026-07-04-ed2k-p9-protocol-completeness-design.md) / [plan](superpowers/plans/2026-07-04-ed2k-p9-protocol-completeness-impl-plan.md)

- [ ] **P9-1 设计 spec**（✅ 已起草）：服务器 UDP 完备/服务器列表交换/MuleInfo/AICH 共享端/压缩上传/aMule .part.met/大文件 + M1-M4 + G1-G9。
- [ ] **P9-2 实现计划**（✅ 已起草）：S1-S7 + 测试门 + 破改分析。
- [ ] **P9-3 服务器 UDP 完备**（M1/S1）：desc/status/ident + GLOBGETSOURCES2/FOUNDSOURCES2 v2。
- [ ] **P9-4 服务器列表交换 + MuleInfo**（M2/S2-S3）：`OP_GETSERVERLIST`/`SERVERLIST`（替换 stub）+ `OP_MULEINFO` 客户端识别。
- [ ] **P9-5 AICH 共享端 + 压缩块上传**（M3/S4-S5）：`CreatePartRecoveryData` 对偶 + `encode_compressed_part` + 收益判定。
- [ ] **P9-6 aMule-faithless .part.met + 大文件**（M4/S6）：aMule 字节级 .part.met（跨客户端续传）+ >4GiB 边界 + 信任+回校验。
- [ ] **P9-7 跨客户端续传 + live**（S7）：aMule ↔ 本节点互导半完成文件续传 + live。

> **v2.2 完成定义**：P5+P6+P7+P8+P9 全完成 = 引擎达到 aMule 协议级全功能对等（除 UI）。

### 阶段 R1 — 代码质量与现代化重构（跨版本，与 P5-P9 正交可并行）

**依赖**：v1.0（229 测试 + live 绿 + aMule 字节保真是重构红线）
**目标**：不改变外部行为，提升封装性/现代 C++/设计模式/线程安全类型强化。为 P5-P9 扩展稳固结构基础。
**设计/实现**：[spec](superpowers/specs/2026-07-04-ed2k-r1-code-quality-refactor-design.md) / [plan](superpowers/plans/2026-07-04-ed2k-r1-code-quality-refactor-impl-plan.md)

- [ ] **R1-1 设计 spec**（✅ 已起草 2026-07-04）：现状评估（带证据）+ M1-M4 + G1-G6。
- [ ] **R1-2 实现计划**（✅ 已起草 2026-07-04）：S1-S8 + 测试门 + 破改分析。
- [x] **R1-3（M1/P0）封装 + 线程安全类型强化**：`IPv4::value` 私有化 ✅ S1（`1b11513`，234/229/5 不回归）+ `MultiSourceDownload` Builder + 注入引用替换裸指针 ✅ S2（`ddb12d7`，234/229/5 不回归）+ disk pool 单线程契约 + `SharedState` executor 归属 debug 断言 ✅ S3（`957372f`，235/230/5 不回归）。
- [ ] **R1-4（M2/P1）结构 + 模式**：`Download::run`/`peer_worker` 拆阶段 + 公共 API PIMPL（藏 Boost）+ Observer RAII Subscription。
- [ ] **R1-5（M3/P2）现代 C++**：`[[nodiscard]]`/`noexcept`/`constexpr` 扫描 + `std::hash` 强哈希 + concepts + `std::format`。
- [ ] **R1-6（M4/P3，延后）C++23 迁移**：`std::expected`/`std::format` 库版 + 基线升 C++23（待 v2.x 协议层稳定）。

> **执行顺序**：R1-3（P0）先于 P5 实现；R1-4 可与 P5 并行；R1-5 任意增量；R1-6 延后。每子任务独立提交 + 229 测试不回归 + aMule 字节保真不动。

---

## 6. v1.0 发布检查清单（Release Checklist）

发布 v1.0 前逐项 ✅：

- [x] R0-1 live 4 测试绿（4/4：Login/Search/GetSources ✅ vs 真实服务器 45.82.80.155:5687 + LocalPeerCompletes ✅ vs 本地 aMule 2.3.3 peer 单 part 5.57MB + 多 part 29MB（hash `262a4f329acf61426f6491d80205037b`，Red 变体）MD4 校验通过；live 反向触发 7 处协议保真 hotfix，见 §5 R0-1；HighIdSourceCompletes 公网源受阻已被 LocalPeerCompletes 取代覆盖）
- [x] R0-2 CI 双平台绿（mock 全过，live skip）— ✅ run `28695894770`（`cf8d4e7`）：Windows-2022 + Ubuntu-latest 双平台 234 测试 229 pass + 5 live skip，0 fail（2026-07-04）。CI workflow：fresh vcpkg clone（cached per-baseline）+ checkout baseline + `VCPKG_BINARY_SOURCES=x-gha` 缓存
- [x] R0-3 Linux + Windows 双平台构建+测试通过 — ✅ CI 双平台绿（见 R0-2）+ 本地 Windows 229 pass（`6fe693f`）。代码静态扫描无 Winsock/`_WIN32`/Windows API（`#ifdef _WIN32` 守卫的 `SO_EXCLUSIVEADDRUSE` 测试代码 Linux 跳过）。Linux/GCC 暴露并修复 1 处单线程调度竞态（`CallbackRequestSendsEncodedFrame`，ACK 同步）
- [x] R0-4 README/USAGE/API 文档完成（✅ 2026-07-03 + 2026-07-04 push-readiness 刷新）
- [x] R0-5 `install()` ✅ + 版本号 `1.0.0` ✅（2026-07-04：`version.cpp`/`CMakeLists.txt`/`vcpkg.json`/`README.md`/`CHANGELOG.md` 全部升 1.0.0）
- [x] R0-6 死代码清理、skip 项登记（D11 接线确认 + skip→test 替换 + 死代码扫描无残留，2026-07-03）
- [x] P4c-2 AICH 两级树互操作完成（OP_AICHFILEHASHREQ/ANS + 两级 Merkle + peer_worker 启用 AICH）
- [x] P4c-3 多源并发 + 续传增强完成（raccoon ✅ + Block u64 ✅ + .part.met 接入 ✅ + 异步磁盘 ✅ + >4GiB 边界 ✅ + M4 live ✅ LocalPeerCompletes vs 本地 aMule peer 单/多 part MD4 校验通过）
- [x] 既有 mock 回环全绿不回归（229 绿 + 5 live skip，见 §3.1）
- [x] CHANGELOG / Release notes（`CHANGELOG.md` + `README.md`，2026-07-03）

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

v1.0 ──► P5(上传/分享/信用) ──► v1.1
v1.0 ──► P6(KAD) ──► v1.2   (P6 可与 P5 并行)
v1.0 ──► P7(混淆) ──► v2.0   (与 P5/P6 正交)
v1.0+P5 ──► P8(客户端基础设施) ──► v2.1
v1.0+P5+P8 ──► P9(eD2k 协议完备) ──► v2.2   (aMule 全功能对等)
```

**v2.2 完成定义**：P5+P6+P7+P8+P9 全完成 = 引擎达到 aMule 协议级全功能对等（除 UI）。

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
| 2026-07-03 | R0-4 完成（README + 用户文档，`fde2fdd`）：`README.md`（简介/协议覆盖/构建 vcpkg+CMake/CLI/架构 single-io_context+raccoon+异步磁盘/Asio gotcha/关键参数/live 门）、`docs/USAGE.md`（7 CLI 子命令详解+示例+退出码+.part.met 续传）、`docs/API.md`（公共 API 按模块概览+并发契约）、`CHANGELOG.md`（Keep a Changelog，P4c-1/2/3+0.1.0）。§4.1 CHANGELOG/release-notes 项勾除 | fde2fdd |
| 2026-07-03 | R0-2/R0-3 脚手架（CI + Linux preset，`85877ff`）：`.github/workflows/build.yml`（Windows MSVC preset `default` + Ubuntu GCC preset `linux` 矩阵，vcpkg manifest，ctest live 默认 skip）；`CMakePresets.json` 新增 `linux` preset（Ninja 单配置）；静态扫描确认库/CLI 无 Winsock/`_WIN32`/Windows API/反斜杠路径（全经 Boost.Asio；`_WIN32_WINNT` 已 `$<PLATFORM_ID:Windows>` 守卫）。⚠️ 无 Linux/CI 环境本地验证，待首次 push 触发 | 85877ff |
| 2026-07-03 | R0-6 完成（死代码/收尾核查，`a66b2ef`）：D11 `encode_callback_request` 全链接线确认（messages→`ServerConnection::callback_request`→download.cpp:101/181 LowID 回调 + `CALLBACKREQUESTED` 解码）；`RequestPartsI64RoundTrip` 占位 skip → 替换为 `Beyond4GiBBoundaryRoundTrip`（绿）；死代码扫描——`filter_high_id`/`fallback_servers`/`build_targets` 均有引用、`udp_*` 为已测未接线技术债（非死代码）、`encode_get_server_list` 为 stub，无可安全移除项。skip 项登记：4 live（§3.1） | a66b2ef |
| 2026-07-03 | R0-1 HighIdSourceCompletes 穷举确认环境受阻：写 `ProbeReachableHighIdSource` 探针（TEMP，验证后移除未提交）批量对 12 个跨多文件的公网 HighID 源做完整 P2P 握手（C2CConnection.connect+handshake），**12/12 全失败**（8 connection_closed + 4 connect_failed），0 个回 HELLOANSWER。结合此前 4 源 recv 诊断（对端协议交换前关闭、未发任何 eMule 帧），确凿结论：非代码缺陷，2026 公网 eMule 源对未知 IP 冷直连一律拒连；framing/HELLO 已对照 aMule 且与 live 服务器登录同路径（绿）。转绿唯一途径=用户提供可靠源。全套 229/229 绿（4 live 无 env skip） | （文档更新，无代码提交） |
| 2026-07-03 | R0-1 live 协议保真修复（`4268716`）：对真实 eMule Security 服务器（45.82.80.155:5687）live 验证暴露两处 aMule 字节级偏离。**① tag 类型**（tag.hpp/cpp 对照 MetaDefs.h EMetaTagTypes）：Hash16=0x01/String=0x02/Uint32=0x03/Float32=0x04/Blob=0x05/Uint16=0x06/Uint8=0x07/BSOB=0x08/Uint64=0x09（原值错乱）；eMule STR1-STR16 短串优化（type 0x11-0x20 即长度，无 2 字节长度前缀，STR_N=0x10+N）——真实服务器以 STR9(0x19) 发 FT_FILENAME="emule.gif"，原报 unsupported_version 致 live 搜索解码失败；read_tag 补 Float32/Uint64/BSOB + STR 区间。**② IP 字节序**（根因：IPv4.value 约定 a 在高位兼容 asio，aMule 内部 IP u32 为 a 在低位——相反）：纯 IP 字段（server.met/服务器列表/回调/peer hello server_ip）改 u32_be 直读 a-high-byte；id 字段（client_id/source.id）保持 u32()（a-low-byte LE）以匹配 LowID 判定（id<0x01000000），连接触用 IPv4::from_wire(id) bswap；ByteReader/Writer 增 u32_be、IPv4 增 from_wire；download.cpp Download::run/fetch_hashset/peer_worker connect 改 from_wire；CLI 改 from_wire(s.id)。测试改真实线序。server.met IP 显示修正。全套 225/229 绿 + live Login/Search/GetSources 绿 | 4268716 |
| 2026-07-03 | R0-1 live 下载协议保真修复（LocalPeerCompletes 多 part 转绿）：对本地 aMule 2.3.3 peer（WSL2 amuled:4662）多 part 29MB live 下载逐字节排查，暴露并修复 7 处 aMule 字节级偏离（详见 §5 R0-1）：① `request_blocks` 多子帧累积（`accumulate_blocks`，aMule `CreateStandardPackets` 切 ~10240B 子帧，原「一区间一帧」假设错）；② 单 part 文件跳过 hashset（aMule `GetHashCount()==0` 静默不应答）；③ HELLO/HELLOANSWER 不对称（HELLO 前导 0x10，拆 `encode_hello_packet`/`decode_hello`）；④ HELLO body 尾部 server_ip:4 BE + server_port:2；⑤ HASHSETANSWER 前导 file_hash:16 校验（`decode_hashset_answer(expected,…)`）；⑥ ed2k 文件哈希默认 Red 变体（PART_SIZE 整数倍追加空尾 part MD4("")）；⑦ **FILESTATUS count=0 = 完整文件**（aMule `ClientTCPSocket.cpp OP_SETREQFILEID`：`!IsPartFile()→WriteUInt16(0)`，原引擎误读为「0 part」致多 part 下载 0 字节，`download.cpp` 两处空位图→`assign(num_parts,true)`）。`PartFile::num_parts` 改 `ceil(size/PART_SIZE)`（Red 空尾 part 不占数据 part 槽）+ 越界守卫。移除 6 处 mock per-batch OUTOFPARTREQS。新增 4 单测。多 part live 绿（hash `262a4f329acf61426f6491d80205037b`，Red，~566s；单 part `101f7523359e85aa7c145f7de489b878` 5.57MB 亦绿，~188s）。全套 229 绿 + 5 live skip | 1387d30 |
| 2026-07-04 | R0-3 本地 WSL 验证启动（暂停）：Ubuntu-24.04 工具链就位（g++ 13.3.0/cmake 3.28.3/ninja 1.11.1 + vcpkg@/opt/vcpkg + 源码@/root/ed2kengine）。**阻塞**：`vcpkg.json` builtin-baseline `15e5f3820f…`（= Windows vcpkg 本地 HEAD）在 WSL fresh clone + unshallow 后不可达，疑上游 rebase 移除；manifest mode 需该 commit 可达（gtest `version>=`）。待解：完整 clone 确认或更新 baseline 为可达 commit。**⚠️ 同样可能阻塞 R0-2 CI**（fresh clone 同需该 commit）——push 前必修。详见 §5 R0-3。用户暂停开发，工作计划同步至文档 | （文档更新，无代码提交） |
| 2026-07-04 | /loop 续行 v1.0 关键路径。**vcpkg baseline 修复**：原 `15e5f3820f…` 上游已不可达 → 更新 `vcpkg.json` builtin-baseline 为稳定 tag `2026.06.24` commit `cd61e1e26a…`（gtest 1.17.0/boost-asio 1.91.0 在版本数据库）。发现并修复 vcpkg manifest versioning 两要求：① 本机 vcpkg HEAD ≥ baseline commit（旧 vcpkg 报 `no version database entry`）→ Windows `D:\tools\vcpkg` + WSL `/opt/vcpkg` 均 checkout baseline commit + bootstrap；② 完整（非 shallow）clone（shallow 缺历史 port tree 对象报 `failed to unpack tree object`）→ WSL `fetch --unshallow`。**CI workflow 重写**（`.github/workflows/build.yml`）：runner vcpkg `git checkout <baseline>` + bootstrap + `VCPKG_BINARY_SOURCES=x-gha` 缓存 + baseline 从 vcpkg.json 动态读取。本地 Windows + WSL Linux 构建进行中（vcpkg 首次编译 Boost 等依赖）。目标仓库 `cool2528/ed2k-engine-cpp` 已推送（`main`@`cfcbff6`），remote 已配置，用户 /loop 授权 GitHub 操作 | （进行中，未提交） |
| 2026-07-04 | **Windows 本地验证 ✅**（`6fe693f`）：baseline 修复后 `cmake --preset default` + build + `ctest -C Debug -j8` → **234 测试 229 pass + 5 skip（live）0 fail**（23.10s）。vcpkg install 6.9min。**CI 迭代调试**（3 轮）：① run `28695358307`（`6fe693f`）：Linux 失败——runner 预装 vcpkg 带 ports/ 本地修改，`git checkout` 报 `local changes would be overwritten`；Windows 失败——`windows-latest` 现 ship VS 18(2025)，`default` preset 的 `Visual Studio 17 2022` 生成器找不到 VS（`could not find any instance of Visual Studio`）。② run `28695428135`（`c6b40bd`，`checkout -f`）：Linux vcpkg setup ✅ + Configure ✅ + Build ✅，但 **Test 失败**——`ctest --preset` 在 `working-directory: build/default` 下找不到 CMakePresets.json（preset 须从源码根调用）；Windows 仍 VS 18 失败。③ run `28695586213`（`e40b495`，fresh vcpkg clone + pin `windows-2022`）：取消（Test 步骤 bug 未修）。④ run `28695626715`（`09ec5ca`）：fresh vcpkg clone（cached per-baseline）+ `windows-2022`（VS 2022 匹配生成器）+ Test 从源码根 `ctest --preset`——**Windows CI ✅ 全绿**（234/229/5）；Linux 233/234 pass，仅 `ServerConnection.CallbackRequestSendsEncodedFrame` 失败（单线程 io_context 调度竞态：客户端 `callback_request` 后无响应等待即 close+rt.stop()，取消服务器挂起 `read_frame(f2)`，Linux/GCC 调度顺序使客户端先停）。⑤ run `28695894770`（`cf8d4e7`）：测试修复——服务器读 f2 后发 SERVERMESSAGE ACK，客户端 `receive_events` 等 ACK 再 close（确定性同步）；Windows 本地全套 234 pass 验证无回归。CI run 5 双平台验证中。WSL 本地 Linux vcpkg 逐 Boost 子包下载过慢（~37min+ 仍 header-only，0 编译库），CI ubuntu-latest 为权威 Linux 验证 | `6fe693f`→`cf8d4e7` |
| 2026-07-04 | **🎉 v1.0.0 已发布**：CI run `28696148779`（`60f15de`，版本号升 1.0.0）**双平台全绿**确认发布提交。R0-2（CI）✅ + R0-3（跨平台）✅ + R0-5（版本 1.0.0）✅。**打 annotated tag `v1.0.0`**（`60f15de`）+ **GitHub Release 发布**：https://github.com/cool2528/ed2k-engine-cpp/releases/tag/v1.0.0 （非 draft、非 pre-release，latest）。§6 发布检查清单全 ✅。**v1.0.0 MVP 下载器发布门达成**。WSL 本地 Linux vcpkg install 完成（49min，11 库），configure+build+test 作为次要本地确认后台续跑（CI 已为权威验证） | `60f15de` + tag `v1.0.0` |
| 2026-07-04 | **WSL 本地 Linux 验证 ✅**（`c31bda9`）：vcpkg install 49min + configure + build + `ctest --preset linux` → 234 测试 229 pass + 5 live skip，0 fail。四重确认（Windows local/CI + Linux CI/WSL） | `c31bda9` |
| 2026-07-04 | **P5-P9 全功能 spec/plan 起草冻结**（用户决策：对标 aMule 全部引擎功能除 UI）。新增 5 spec + 5 plan（`docs/superpowers/{specs,plans}/2026-07-04-ed2k-p{5..9}-*.md`）：P5 上传/分享/信用（M1-M4/S1-S8）、P6 KAD（M1-M4/S1-S7）、P7 协议混淆（M1-M4/S1-S6）、P8 客户端基础设施（M1-M5/S1-S8）、P9 eD2k 协议完备性（M1-M4/S1-S7）。每份含逐帧字节级协议设计（对照 aMule 源码模块）+ 里程碑 + 陷阱清单 G1-G9 + 测试门 + 既有测试破改分析 + live 验证计划。RELEASE-PLAN §1.1/§2/§5/§7 同步扩展为 v1.0→v2.2 五阶段路线图。**v2.2 完成定义**：P5+P6+P7+P8+P9 全完成 = aMule 协议级全功能对等（除 UI） | （文档，无代码提交） |
| 2026-07-04 | **ChatRelay 并入 P8**（用户决策）：聊天消息中继（`OP_MESSAGE` 0x4E server-relayed + C2C）作为与 HTTPThread 同级模块纳入 P8 M5/S7。P8 spec 加 §3.6 ChatRelay 设计 + G10 陷阱（帧格式字节对照 aMule `ProcessMessage`、LowID 走服务器中继/HighID 走 C2C、UTF-8/latin1）；plan S7 加 ChatRelay 实现 + 测试门（≥7 测试）；RELEASE-PLAN §1.1/§2/§5 P8 行同步。至此 eMule 全部引擎功能（含 chat）均有 spec/plan 覆盖，无缺口 | （文档，无代码提交） |
| 2026-07-04 | **R1 代码质量重构 spec/plan 起草冻结**（用户反馈：封装性差/现代 C++ 不优雅/设计模式少/线程安全脆弱）。新增 [spec](superpowers/specs/2026-07-04-ed2k-r1-code-quality-refactor-design.md)+[plan](superpowers/plans/2026-07-04-ed2k-r1-code-quality-refactor-impl-plan.md)：现状评估带证据（`IPv4::value` public、`MultiSourceDownload` 8 参裸指针、`on_event` 无退订、`SharedState` 裸 bool 约定正确性、无 PIMPL/Builder/状态机、`std::hash` 弱哈希等）+ M1-M4（P0 封装+线程安全类型强化 / P1 PIMPL+拆阶段+Observer / P2 现代 C++ / P3 延后 C++23）+ S1-S8 green-deployable + G1-G6 + 测试门。纪律：行为保持 + 229 测试不回归 + aMule 字节保真不动。RELEASE-PLAN §5 加「阶段 R1」+ §7 标注正交可并行。**先做 R1-3（P0），与 P5 实现串行** | （文档，无代码提交） |
| 2026-07-04 | **R1-3 S1 完成**（`1b11513`）：`IPv4::value` 私有化 → `value_` + `constexpr from_host()/host()` 访问器。8 处聚合初始化 `IPv4{u32}`→`from_host`，14 处成员访问 `.value`/`->value`→`.host()`/`->host()`（`expected::value()`/`optional::value()` 带括号者非 IPv4 成员，不动）。`from_wire` bswap 语义不变（aMule 字节保真）。Windows 234 测试 229 pass + 5 live skip，0 fail，行为保持 | `1b11513` |
| 2026-07-04 | **R1-3 S2 完成**（`ddb12d7`）：`MultiSourceDownload::Builder` 提供 `.out/.hash/.size/.aich/.sources/.server/.listener/.disk_executor` 链式构造；内部 `ServerConnection*`/`InboundListener*` 改为 `std::optional<std::reference_wrapper<...>>` 非拥有注入引用；旧构造与 `set_disk_executor` 标记 deprecated 保留兼容。`server_session`、下载/LowID/live 测试迁移到 Builder，异步磁盘卸载测试改走 `Builder.disk_executor()`。Windows `cmake --build build/default --config Debug --target ed2k_tests && ctest -C Debug -j8 --output-on-failure`：234 测试 229 pass + 5 live skip，0 fail。R1 不改协议帧语义 | `ddb12d7` |
| 2026-07-04 | **R1-3 S3 完成**（`957372f`）：`IoRuntime::disk_pool_thread_count=1` 成为类型级契约并驱动 `thread_pool` 初始化，注释明确改 >1 前必须给 `PartFile::f_` 加 strand/串行化；`SharedState` 增 debug owner thread 断言，`set_error`/`dec_active_workers`/`mark_complete` 收束状态突变，替代 worker 裸写。新增 `Download.DiskPoolIsSingleThreadByContract`，Windows `cmake --build build/default --config Debug --target ed2k_tests && ctest -C Debug -j8 --output-on-failure`：235 测试 230 pass + 5 live skip，0 fail。**R1-3 M1/P0 全完成** | `957372f` |
| 2026-07-04 | **P5-1/P5-2/P5-3 S1 完成**（`499b722`）：P5 spec/plan 既有冻结文档勾选；新增 `share::KnownFile`/`KnownFileDB`，支持 `known.met` 共享层 round-trip（FT_FILENAME/FT_FILESIZE/FT_AICH_FILEHASH）、`known2.met` per-file AICH root + leaves round-trip、目录扫描建索引（ED2K Red hash + AICH root）和 `PartFile::to_known_file()` 完成文件迁移。修复 `codec::write_tag`：`uint64_t` 值超过 u32 时写 `TAGTYPE_UINT64`，避免 >4GiB 文件大小截断。新增 4 个 `ShareKnownFile.*` 测试；Windows `cmake --build build/default --config Debug --target ed2k_tests && ctest -C Debug -j8 --output-on-failure`：239 测试 234 pass + 5 live skip，0 fail | `499b722` |
| 2026-07-04 | **P5-4 S2 完成**（`45d72e7`）：新增 `OP_OFFERFILES`(0x15) + `FT_AICH_FILEHASH`(0x11)，实现 `encode_offer_files(std::span<const share::KnownFile>)`（count + per-file hash + FT_FILENAME/FT_FILESIZE/FT_AICH_FILEHASH tag 顺序，>4GiB size 保持 u64）和 `ServerConnection::publish_files`；CLI 新增 `ed2k-tool publish <dir> [--server:server.met] [--ip:x.x.x.x] [--port:n]`，复用 `KnownFileDB::scan_dir` + `login_with_rotation` 发布共享目录。新增 3 个 `ServerMessages/ServerConnection` 测试（含多文件 count/order + mock server 收帧）；Windows `cmake --build build/default --config Debug --target ed2k_tests ed2k-tool` + `ctest -C Debug -j8 --output-on-failure`：242 测试 237 pass + 5 live skip，0 fail。按用户要求仅本地提交，未 push/未触发 GitHub Actions | `45d72e7` |
| 2026-07-04 | **P5-5 S3 完成**（`a5ca1db`）：新增上传端 C2C 对偶消息 `decode_file_hash_request`/`encode_req_filename_answer`/`encode_file_status`/`encode_hashset_answer`；新增 `share::UploadSession`，acceptor 握手后响应 `REQUESTFILENAME`→`REQFILENAMEANSWER`、`SETREQFILEID`→完整文件 `FILESTATUS count=0`、`HASHSETREQUEST`→`HASHSETANSWER`（单 part hashset 空时静默不应答，保持 aMule 对称语义）。新增 5 个 S3 测试（4 消息字节 + 1 socket 会话）；Windows `cmake --build build/default --config Debug --target ed2k_tests ed2k-tool` + `ctest -C Debug -j8 --output-on-failure`：247 测试 242 pass + 5 live skip，0 fail。按用户要求仅本地提交，未 push/未触发 GitHub Actions | `a5ca1db` |
| 2026-07-04 | **P5-5 S4 完成**（`c3f3e7d`）：`UploadSession` 新增 disk executor 注入，`REQUESTPARTS` 从共享文件按 `[start,end)` 读盘并按 aMule `CreateStandardPackets` 约 10240B 子帧发送 `OP_SENDINGPART`；新增 `OP_AICHFILEHASHREQ`→`OP_AICHFILEHASHANS` 和 `OP_AICHREQUEST`→`OP_AICHANSWER`，上传端按下载端 `AICHChecker` 对偶规则生成两级 V2 recovery data（left-biased split + identifier 路径，支持 16/32-bit identifier 编码）；`net::Connection` 暴露 executor 便于读盘后切回网络 executor。新增 8 个 S4 测试（REQUESTPARTS/SENDINGPART/AICH answer 字节、块上传 MD4 数据一致、子帧切分、AICH master、AICH recovery 经生产 `AICHChecker` 验证）；Windows `cmake --build build/default --config Debug --target ed2k_tests ed2k-tool` + `ctest -C Debug -j8 --output-on-failure`：255 测试 250 pass + 5 live skip，0 fail。按用户要求仅本地提交，未 push/未触发 GitHub Actions | `c3f3e7d` |
| 2026-07-04 | **P5-6 S5 完成**（`350a100`）：新增 `share::UploadQueue`，支持 slot 容量、排队排名、释放 slot 后队首 reask 授权、禁止新 peer 插队；C2C 新增 `encode_queue_ranking` 以及 aMule UDP `OP_REASKFILEPING`(0x90)/`OP_REASKACK`(0x91)/`OP_QUEUEFULL`(0x93) 常量和字节编码（aMule TCP `STARTUPLOADREQ`/`ACCEPTUPLOADREQ`/`QUEUERANKING` 保持既有 0x54/0x55/0x60）。`UploadSession` 保存 peer `user_hash`，收到 `STARTUPLOADREQ` 时按队列返回 `ACCEPTUPLOADREQ` 或 `QUEUERANKING`，连接关闭时从队列移除。新增 9 个 S5 focused 测试（队列 slot/排名/重询、queue ranking/reask 字节、session accept/rank/reask accept）；Windows `cmake --build build/default --config Debug --target ed2k_tests ed2k-tool` + `ctest -C Debug -j8 --output-on-failure`：264 测试 259 pass + 5 live skip，0 fail。按用户要求仅本地提交，未 push/未触发 GitHub Actions | `350a100` |
| 2026-07-04 | **P5-6 S6 完成**（`a02e6e8`）：新增 `share::UploadBandwidthThrottler`，以 `steady_timer` 在协程中等待发送配额，back-to-back acquire 按字节速率延后且不阻塞同一 `io_context` 中其他协程；`UploadSession` 增加可选 throttler 注入，在发送 `OP_SENDINGPART` 子帧前按数据字节 acquire，实现上传块发送限速。新增 3 个 S6 测试（连续 acquire 延迟、等待期间其他 coroutine 可运行、`UploadSession` 分片发送限速）；Windows `cmake --build build/default --config Debug --target ed2k_tests ed2k-tool` + `ctest -C Debug -j8 --output-on-failure`：267 测试 262 pass + 5 live skip，0 fail。按用户要求仅本地提交，未 push/未触发 GitHub Actions | `a02e6e8` |
| 2026-07-04 | **P5-6 S7 完成**（`c120c20`）：新增 `share::ClientCredits` + M3 简化 `clients.met` round-trip（key=`user_hash`，RSA/公钥校验留 P9），记录 uploaded/downloaded 并按 `(uploaded-downloaded)` 计算 score；`UploadQueue` 可注入 `ClientCredits`，满 slot 时按信用分排序且同分保持 FIFO；`UploadSession` 发送 `OP_SENDINGPART` 成功后对 peer `user_hash` 记账 uploaded bytes。新增 4 个 S7 测试（credits round-trip、score、信用影响队列顺序、上传块记账）；Windows `cmake --build build/default --config Debug --target ed2k_tests ed2k-tool` + `ctest -C Debug -j8 --output-on-failure`：271 测试 266 pass + 5 live skip，0 fail。按用户要求仅本地提交，未 push/未触发 GitHub Actions | `c120c20` |
| 2026-07-04 | **P5-7 S8 完成**（`37c5f25`）：补齐 aMule C2C 共享/SourceExchange/评论评分基线：`OP_ASKSHAREDFILES`(0x4A)/`OP_ASKSHAREDFILESANSWER`(0x4B)、SX2 `OP_REQUESTSOURCES2`(0x83)/`OP_ANSWERSOURCES2`(0x84, eMule protocol)、`OP_FILEDESC`(0x61) 常量与 payload 编解码；`C2CConnection::request_sources2` 发送 SX2 请求并校验 answer hash；`UploadSession` 可返回本机 shared files 列表、对已知文件返回空 SX2 source list、解析并忽略 `FILEDESC`。新增 7 个 focused 测试（shared files answer、SX2 request/answer、file desc、session shared/SX2 响应、C2C SX2 round-trip）；Windows `cmake --build build/default --config Debug --target ed2k_tests ed2k-tool` + `ctest -C Debug -j8 --output-on-failure`：278 测试 273 pass + 5 live skip，0 fail。按用户要求仅本地提交，未 push/未触发 GitHub Actions；live 对 aMule peer 留 P5-8 | `37c5f25` |
| 2026-07-04 | **P5-8 进展**（`1e79125`，未勾完成）：评论/评分从单纯编解码推进到同步路径——`KnownFile` 增 `rating/comment`，`KnownFileDB::set_file_desc` 写回当前文件，`UploadSession` 保存当前 requested file 并在收到 `OP_FILEDESC` 后更新评论；`C2CConnection::send_file_desc` 支持出站 eMule `FILEDESC`；CLI 新增 `ed2k-tool comment <ed2k-link> --rating:n --comment:text [--peer:ip:port]`，无 peer 时输出 payload，有 peer 时 handshake + `SETREQFILEID` + 发送评论；新增 `LiveUpload.SourceExchange2WithLocalPeer` 和 `LiveUpload.AcceptsLocalPeerUploadSession` 两个门控 harness（默认 skip），并更新 `USAGE.md`/`API.md`。验证：focused `C2CConnection.SendsFileDesc` + `UploadSession.StoresFileDescForCurrentRequestedFile` 绿；`cmake --build build/default --config Debug --target ed2k_tests ed2k-tool` + `ctest -C Debug -j8 --output-on-failure`：282 测试 275 pass + 7 live skip，0 fail。按用户要求仅本地提交，未 push/未触发 GitHub Actions；真实 aMule P5 live 仍待执行 | `1e79125` |
| 2026-07-04 | **P5-8 SX2 live 调试进展**（未勾完成）：`OP_REQUESTSOURCES2` 新增专用解码器，上传端兼容 hash-only 与 `version/options/hash` payload；`LiveUpload.SourceExchange2WithLocalPeer` 在 SX2 前先 `SETREQFILEID`，贴近 aMule `CreateSrcInfoPacket` 的文件上下文要求。WSL aMule 2.3.3 live 证据：19B standalone SX2 会被 aMule 接收端断开，hash-only standalone 保持连接但因当前 aMule `Clients in queue=0`/`Total sources=0`、`CKnownFile::CreateSrcInfoPacket` 在 source 列表为空时返回 NULL，测试仍以 `operation timed out` 失败；需后续构造第二 source 才能完成真实 source exchange。验证：focused SX2/C2C/UploadSession 5 测试绿；Windows `cmake --build build/default --config Debug --target ed2k_tests ed2k-tool` + `ctest -C Debug -j8 --output-on-failure`：284 测试 277 pass + 7 live skip，0 fail。按用户要求仅本地验证/提交，未 push/未触发 GitHub Actions | 本地提交 |
| 2026-07-05 | **P5-8 SX2 非空源列表进展**（未勾完成）：`KnownFile` 增运行时 `sources`（不写 known.met），`UploadSession` 对 `REQUESTSOURCES2` 返回 `file->sources`，新增 `UploadSession.AnswersRequestSources2WithKnownSources` 锁定非空 `ANSWERSOURCES2` 字节路径；既有空源列表行为保持。Windows `cmake --build build/default --config Debug --target ed2k_tests ed2k-tool -- /m` + `ctest -C Debug -j8 --output-on-failure`：285 测试 278 pass + 7 live skip，0 fail。live 证据：WSL aMule 2.3.3 daemon 成功启动并共享 1 MiB 文件；本节点 `publish` 同 hash 到 ed2k-rust 成功；`LiveUpload.SourceExchange2WithLocalPeer` 仍因 aMule `Total sources=0` 不发 `ANSWERSOURCES2` 超时。另用 source-extended link `|sources,172.22.32.1:4663|` 尝试触发 aMule 拉本节点上传，aMule 接受 link 但仍显示 `0/0 Waiting` / `Total sources=0`，未连接 upload harness。P5-8 live 未完成，下一步需构造 aMule 实际纳入 source list 的第二源或改进 live harness 驱动方式 | `5a1a052` |

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
