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
> **最近更新**：2026-07-04 — **🎉 v1.0.0 已发布**（tag `v1.0.0` @ `60f15de`，[GitHub Release](https://github.com/cool2528/ed2k-engine-cpp/releases/tag/v1.0.0)）。CI 双平台绿 + 全部发布检查清单 ✅。

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
| **P4c-3 多源并发 + 续传增强** | raccoon 多源并发 + 块粒度续传 + `peer::Block` u64 + 异步磁盘 I/O + .part.met 接入下载流程 | ✅ M1✅ M2✅ M3✅ M4✅（raccoon 并发骨架+多源 e2e+.part.met 续传+异步磁盘卸载+>4GiB 边界+**M4 live vs 本地 aMule 2.3.3 peer 单/多 part MD4 校验通过**） |

---

## 3. 当前状态快照（2026-07-03）

### 3.1 构建 & 测试

```
cmake --build build/default --config Debug --target ed2k_tests ed2k-tool  → 成功
./ed2k_tests.exe                                                          → 234 tests, 229 PASSED, 5 SKIPPED (live 门控)
```

> 全套 mock 回环 229 绿 + 5 live skip（默认无 `ED2K_LIVE`）。5 个 live 测试 = 3 `LiveServer.*` + `LiveDownload.HighIdSourceCompletes` + `LiveDownload.LocalPeerCompletes`。**live 实测**：3 `LiveServer.*` 绿（vs 45.82.80.155:5687，`4268716`）；`LocalPeerCompletes` 绿（vs 本地 aMule 2.3.3 peer，单 part 5.57MB + 多 part 29MB 全程 MD4 校验通过，见 §5 R0-1）。`HighIdSourceCompletes` 仍环境受阻（公网源冷连被拒，非代码缺陷），已被 `LocalPeerCompletes`（直连可靠本地 peer）覆盖取代。

跳过的 5 个测试（均 live 门控，默认 skip）：
- `LiveServer.LoginReturnsId` / `SearchReturnsResults` / `GetSourcesReturnsOk` — **门控 live 测试**，设 `ED2K_LIVE` 后绿
- `LiveDownload.HighIdSourceCompletes` — **门控 live 下载测试**，公网源受阻（见 R0-1）
- `LiveDownload.LocalPeerCompletes` — **门控 live 下载测试**，设 `ED2K_LIVE + ED2K_LINK + ED2K_SOURCE` 后绿（vs 本地 aMule peer）

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
