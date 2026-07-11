# ed2k-engine-cpp

[English](README.md)

一个从零开始、使用 C++20 实现的 **eDonkey2000 / eMule (eD2k) 协议**引擎——
支持链接解析、服务器与 Kad 会话、上传/共享、带 AICH 损坏恢复的多源下载，
以及跨客户端断点续传。
基于 Boost.Asio 协程构建，采用单网络线程、无锁设计。

> **协议保真准则。** 所有线协议格式都通过逐字节对比 aMule 源码进行验证
>（操作码、帧布局、两级 AICH Merkle 树、REQUESTPARTS 三范围编码），
> 并在实时测试中与真实的 aMule 2.3.3 对等端完成确认。
> 字节级保真没有例外。

## 状态

| 领域 | 状态 |
|---|---|
| 链接 / `server.met` / 哈希（ed2k + AICH + RED） | ✅ |
| 服务器会话（登录 / 搜索 / 获取来源，HighID + LowID 回调） | ✅ |
| 单源下载 + AICH 两级互操作 | ✅ |
| **多源并发下载（raccoon）** | ✅ |
| `.part.met` 断点续传（met 优先，无需重新哈希） | ✅ |
| 异步磁盘 I/O（卸载到磁盘线程，网络永不阻塞） | ✅ |
| `>4GiB` 边界（u64 块 / 偏移量） | ✅ |
| 真实对等端实时验证 | ✅ 对本地 aMule 2.3.3 + 真实 eMule 服务器（参见[实时测试](#live-tests)） |
| 上传/共享/积分 + SourceExchange v2 | ✅ |
| Kad 引导/搜索/来源查找/发布 | ✅ |
| TCP/UDP/服务器混淆 | ✅ |
| 客户端基础设施（IPFilter、偏好设置、统计、代理、合集、调度器、聊天） | ✅ |
| 服务器 UDP 完整支持 / MuleInfo / 压缩上传 / aMule `.part.met` | ✅ |
| Linux / CI | ✅ |

最新完整 Windows 测试套件：**504/504 项均有结果**（483 项通过 + 21 项预期的环境/实时/CLI 跳过）。
实时路径涵盖服务器、Kad、下载、上传和跨客户端断点续传验证。版本：`2.2.0`。

## 构建

要求：**CMake ≥ 3.24**、**vcpkg**（已设置 `VCPKG_ROOT`）、C++20，以及支持 C++20 的编译器。

**Windows**（Visual Studio 2022，`default` 预设）：

```bash
cmake --preset default            # 配置（vcpkg 清单模式，x64 Debug）
cmake --build build/default       # 构建 ed2k_core + ed2k-tool + ed2k_tests
ctest --preset default            # 运行测试（工作目录为 build/default）
# 构建产物：build/default/Debug/ed2k-tool.exe、ed2k_tests.exe
```

**Linux**（GCC ≥ 13、Ninja，`linux` 预设）：

```bash
cmake --preset linux              # 配置（vcpkg 清单、Ninja、Debug）
cmake --build --preset linux      # 构建
ctest --preset linux              # 运行测试（未设置 ED2K_LIVE 时跳过实时测试）
# 构建产物：build/linux/ed2k-tool、ed2k_tests
```

### 安装并供其他 CMake 项目使用

先配置、构建 ed2k，并将其安装到指定前缀：

```bash
cmake --preset linux
cmake --build --preset linux
cmake --install build/linux --prefix "$PWD/build/stage"
```

独立的 C++20 消费者项目随后可以使用已安装的包：

```cmake
cmake_minimum_required(VERSION 3.24)
project(app LANGUAGES CXX)

find_package(ed2k 2.2 CONFIG REQUIRED)

add_executable(app main.cpp)
target_compile_features(app PRIVATE cxx_std_20)
target_link_libraries(app PRIVATE ed2k::core)
```

配置消费者项目时，需确保能找到该安装前缀，例如：

```bash
cmake -S path/to/app -B path/to/app/build \
  -DCMAKE_PREFIX_PATH="$PWD/build/stage"
cmake --build path/to/app/build
```

导出包不会捆绑其依赖。`spdlog`、`tl-expected`、Zlib、OpenSSL、Boost.Asio 和
Threads 也必须可被发现，通常可以使用同一个 vcpkg 工具链，或在
`CMAKE_PREFIX_PATH` 中添加其他前缀。

Push 和拉取请求 CI 覆盖 Windows 和 Ubuntu 上的 Debug 与 Release。每个矩阵项都会
完成配置、构建、测试、安装，随后针对已安装包完成独立消费者的配置、构建与运行。
实时测试仍为选择性启用，不会阻塞该 CI 矩阵。

## CLI — `ed2k-tool`

```
ed2k-tool [--config <preferences.dat>] [--ipfilter <ipfilter.dat>] [--proxy <uri>] [--obfuscation] <command> ...
ed2k-tool hash <file> [--aich] [--red]                 # 计算 ed2k 链接
ed2k-tool serverlist <server.met>                       # 解析 server.met
ed2k-tool get-serverlist <server.met>                   # 获取并合并 server.met
ed2k-tool parse <ed2k-link>                             # 解析 ed2k:// 链接
ed2k-tool login <server.met> [--ip:x.x.x.x] [--port:n]  # 登录服务器
ed2k-tool search <server.met> <keyword>                 # 关键词搜索
ed2k-tool sources <server.met> <ed2k-link>              # 获取文件来源
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
ed2k-tool kad-bootstrap <nodes.dat>                     # 引导 Kad 路由
ed2k-tool kad-search <nodes.dat> <keyword>              # Kad 关键词搜索
ed2k-tool kad-find-sources <nodes.dat> <ed2k-link>      # Kad 来源查找
ed2k-tool kad-publish <nodes.dat> <dir> [--port:n]      # 将共享内容发布到 Kad
ed2k-tool download <ed2k-link> [--out:PATH] [--server:server.met]
```

### 示例

```bash
# 将文件哈希为 ed2k 链接（包含用于损坏恢复的 AICH 根哈希）
ed2k-tool hash movie.avi --aich
# -> ed2k://|file|movie.avi|734003200|<md4>|h=<aich-base32>|/

# 登录服务器（自动轮换使用 server.met 中的服务器）
ed2k-tool login server.met
# -> client_id=0xXXXX high_id=1 flags=0x...

# 搜索 + 获取来源 + 下载
ed2k-tool search server.met "ubuntu"
ed2k-tool sources server.met "ed2k://|file|ubuntu.iso|...|/"
ed2k-tool download "ed2k://|file|ubuntu.iso|...|/" --out:ubuntu.iso --server:server.met

# Kad 引导/搜索/来源查找
ed2k-tool kad-bootstrap nodes.dat
ed2k-tool kad-search nodes.dat "ubuntu"
ed2k-tool kad-find-sources nodes.dat "ed2k://|file|ubuntu.iso|...|/"
```

`update-serverlist` 接受 HTTP 和 HTTPS URL。HTTPS 始终验证证书链和请求的主机名，
不提供绕过验证的不安全选项。该命令在同一个总体截止时间内最多跟随五次重定向，
允许 HTTP 重定向到 HTTPS，但拒绝 HTTPS 降级重定向到 HTTP。成功的 2xx 响应（包括 `206`）
必须提供 `Content-Length`；不支持 chunked 和以连接关闭为结束标志的响应体。只有当完整的
已声明响应体已写入且文件数据已刷盘后，才会以原子方式替换目标文件。在不支持目录 fsync 的平台上，
父目录的崩溃持久性仅为尽力保证。

未指定 `--server` 时，`download` 会回退到内置的备用服务器列表。下载的文件通过稀疏
`PartFile` 写入，支持逐分块 MD4 验证和 `.part.met` 断点续传——重新运行未完成的下载时，
会跳过已验证的分块，而无需重新计算哈希。

## 架构

**单个 `io_context`，单个网络线程。** 所有引擎状态（`BlockAllocator`、`PartFile`
状态、`first_err`）仅由网络线程访问 → **无锁、无互斥锁、无
`condition_variable`**（条件变量会使单线程 io_context 死锁）。

- **raccoon 多源下载**（`MultiSourceDownload`）：通过 `co_spawn(detached)` 启动的 N 个
  `peer_worker` 协程共享一个 `BlockAllocator`/`PartFile`。每个工作协程获取其对等端
  拥有的块（通过 `next_block_for_parts(has_part)` 按分块位图筛选）。完成事件由
  `asio::experimental::channel<void(ec,int)>` 发出——前导 `ec` = 操作状态，错误通过共享的
  `first_err` 传递。来源耗尽 → 工作协程退出。
- **AICH 两级 Merkle 树**（忠实于 aMule）：每个分块包含叶节点（每个分块 53 个块，最后一个块
  与分块边界对齐），`AICHChecker` 使用证明哈希重建树，以绑定可信的主哈希。
  `peer_worker` 通过 `OP_AICHFILEHASHREQ/ANS` 协商主哈希；不匹配 → 平稳降级为仅使用 MD4。
- **异步磁盘 I/O**：`PartFile::write_block_async` 在独立的磁盘执行器上运行
  `f_.seekp/write` 和分块 MD4 回读（`IoRuntime::disk_executor()` = `thread_pool{1}`，
  单线程串行访问 `f_` → 无需 strand）。只有网络线程会更改状态。状态与 I/O 分离通过
  使用 `bind_executor` 的两次 post 跳转来保证（参见 [Asio 注意事项](#asio-gotcha)）。
- **`.part.met` 断点续传**：`PartFile` 构造函数采用 met 优先策略——有效的 `.part.met`
  （magic + hash + part_hashes 匹配）会根据 gaps 恢复 `part_done_`/`block_done_`，
  **无需重新哈希**；文件缺失/损坏/过期 → 回退到 `rehash_all`。分块完成后会持久化 `.part.met`。

<a id="asio-gotcha"></a>

### Asio 注意事项

`co_await asio::post(ex, use_awaitable)` 会在协程的**关联**执行器（网络线程）上恢复协程，
**而不是**在 `ex` 上——因此磁盘写入仍会在网络线程上运行（没有卸载）。必须使用
`asio::post(ex, asio::bind_executor(ex, asio::use_awaitable))` 强制在 `ex` 上恢复。
`DiskExecutorRunsOnSeparateThread` 测试对此提供固定保障。

### 关键参数

| 参数 | 值 |
|---|---|
| `PART_SIZE` | 9,728,000 字节 |
| `AICH_BLOCK_SIZE` | 184,320 字节（完整分块 = 53 个块，最后一个 = 143,360） |
| `peer::Block.start/end` | `u64`（可安全处理 >4GiB） |
| REQUESTPARTS 范围 | 每个请求包含 3 × `[start,end)` |

<a id="live-tests"></a>

## 实时测试

实时测试受 `ED2K_LIVE` 控制，默认跳过（模拟环回测试不受影响）：

```bash
# 服务器会话（登录 / 搜索 / 获取来源）— 真实 eMule 服务器
ED2K_LIVE=1 ED2K_SERVER=ip:port ED2K_LINK="ed2k://|file|...|/" \
  ED2K_EXPECT_MD4=<hex> ctest --preset default -R Live

# 对等端下载（LocalPeerCompletes）— 直连 eMule/aMule HighID 对等端
ED2K_LIVE=1 ED2K_LINK="ed2k://|file|...|/" ED2K_SOURCE=ip:port \
  ED2K_EXPECT_MD4=<hex> ./build/default/Debug/ed2k_tests.exe \
    --gtest_filter=LiveDownload.LocalPeerCompletes
```

**实时验证 ✅**：服务器登录/搜索/来源查找、Kad 引导/搜索、SX2 上传、本地对等端下载，
以及双向 aMule `.part.met` 交接均已通过真实基础设施或本地 aMule 2.3.3 对等端验证。
公共 HighID 对等端经常会过滤云 IP，因此本地 aMule 实例仍是进行可重复实时测试的可靠对等端来源。

## 项目布局

```
apps/cli/         ed2k-tool CLI
include/ed2k/     公共头文件（net、peer、server、download、hash、codec、link、metfile）
src/              库源文件（镜像 include/ 布局）
tests/            GoogleTest（单个 ed2k_tests 可执行文件；live_* 受 ED2K_LIVE 控制）
docs/             RELEASE-PLAN.md（权威进度跟踪文档）、specs/、plans/
```

## 致谢

[aMule](https://github.com/amule-project/amule) 源码是线协议格式的权威参考；
这里的每个操作码、帧布局和哈希变体都与其进行了逐字节对比。

## 许可证

本项目采用 [MIT 许可证](LICENSE)发布。
