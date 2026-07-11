# 用法 — `ed2k-tool` 命令参考

[English](USAGE.md)

`ed2k-tool` 是 ed2kengine 库的命令行前端。使用服务器的命令可能会在
`server.met` 中的条目之间轮换；超时行为由各命令自行定义。

## `hash <file> [--aich] [--red]`

计算本地文件的 ed2k 链接。

- `--aich` — 同时计算 AICH 根哈希（base32），并以 `h=<root>` 的形式嵌入链接，用于在下载
  过程中恢复损坏的数据。
- `--red` — 使用 RED（eD2k-hash-redefined）哈希变体，而不是经典的 Blue 变体。

```bash
ed2k-tool hash movie.avi --aich
# ed2k://|file|movie.avi|<size>|<md4>|h=<aich-base32>|/
```

## `serverlist <server.met>`

解析 `server.met` 文件并输出服务器表（IP、端口、最大用户数、名称）。

## `update-serverlist <url> <dest>`

从 HTTP 或 HTTPS URL 下载服务器列表到 `dest`。HTTPS 会验证证书链和 URL 中的
主机名，且不提供禁用验证的选项。重定向最多五次，并与连接、TLS 握手和响应
传输共用同一个 15 秒总体截止时间。
允许 HTTP 重定向到 HTTPS，但拒绝 HTTPS 降级重定向到 HTTP。

每个成功的 2xx 响应（包括 `206`）都必须提供 `Content-Length`；不支持 chunked 和以连接关闭
为结束标志的响应体。只有当完整的已声明响应体已写入且文件数据已刷盘后，才会以原子方式
替换目标文件。在不支持目录 fsync 的平台上，父目录的崩溃持久性仅为尽力保证；失败时不会公布
不完整的响应体。

```bash
ed2k-tool update-serverlist https://example.org/server.met server.met
```

## `parse <ed2k-link>`

解析 `ed2k://` 链接并输出其字段。可识别文件、服务器和服务器列表链接。

```bash
ed2k-tool parse "ed2k://|file|ubuntu.iso|12345678|<md4>|/"
# file: name=ubuntu.iso size=12345678 hash=<md4> aich=- sources=0
```

## `login <server.met> [--ip:x.x.x.x] [--port:n]`

登录服务器（依次尝试 `server.met` 中的服务器，直到有一台接受登录）。输出分配到的客户端
ID、该客户端是否为 HighID，以及服务器标志。

- `--ip` / `--port` — 固定使用指定服务器，而不是轮换服务器。

HighID 表示客户端可从公网直接访问；LowID 表示服务器将通过回调
（`OP_CALLBACKREQUEST`）中继连接——引擎会透明地处理这两种情况。

## `search <server.met> <keyword>`

登录服务器、执行关键词搜索并输出结果（`hash  size  name`）。使用第一台匹配的服务器。

## `sources <server.met> <ed2k-link>`

登录服务器，请求给定文件链接的来源并输出这些来源
（`IP  id=0x...  port=...  HighID/LowID`）。

## `publish <dir> [--server:server.met] [--ip:x.x.x.x] [--port:n]`

扫描本地共享目录，在内存中构建已知文件索引，登录服务器，然后使用 `OP_OFFERFILES`
发布文件。

- `--server:server.met` — 登录时使用的服务器列表。省略此选项则使用内部备用列表。
- `--ip` / `--port` — 固定使用指定服务器，而不是轮换服务器。

```bash
ed2k-tool publish D:\share --server:server.met
# published 3 files
```

## `comment <ed2k-link> --rating:n --comment:text [--peer:ip:port]`

编码或发送文件评分/评论（`OP_FILEDESC`）。评分范围为 `0..5`。

不指定 `--peer` 时，该命令会验证链接并输出准确的载荷字节，便于检查协议：

```bash
ed2k-tool comment "ed2k://|file|shared.bin|1|00112233445566778899aabbccddeeff|/" --rating:5 --comment:verified
# file=00112233445566778899aabbccddeeff rating=5 comment=verified payload=05080000007665726966696564
```

指定 `--peer` 时，该命令会连接到对等节点，执行 C2C 握手，设置请求的文件上下文，
并通过 eMule 协议发送 `OP_FILEDESC`。

## `kad-bootstrap <nodes.dat>`

加载 KAD `nodes.dat`，创建本地 Kad2 UDP 节点，并通过列出的联系人进行引导。
输出已加载的种子数、已学习的路由表条目数和绑定的 UDP 端口。

```bash
ed2k-tool kad-bootstrap nodes.dat
# kad contacts: loaded=42 routing=17 udp_port=4672
```

## `kad-search <nodes.dat> <keyword>`

通过 `nodes.dat` 进行引导，推导 Kad 关键词目标，并搜索 Kad 网络。结果以
`kad-answer-id  size  name` 的格式输出。

```bash
ed2k-tool kad-search nodes.dat ubuntu
```

## `kad-find-sources <nodes.dat> <ed2k-link>`

通过 `nodes.dat` 进行引导，并向 Kad 查询链接中文件哈希的来源。直接可达的 HighID
来源会连同其 IP、TCP/UDP 端口、来源类型和 Kad 应答 ID 一起输出。

```bash
ed2k-tool kad-find-sources nodes.dat "ed2k://|file|ubuntu.iso|...|/"
```

## `kad-publish <nodes.dat> <dir> [--port:n]`

扫描本地共享目录，并向距离最近的 Kad 联系人发布来源和关键词记录。
索引器会添加来自 UDP 发送端点的发布者 IP，与 aMule 的 Kad 来源发布行为保持一致。

- `--port:n` — 在 `TAG_SOURCEPORT` 中公布的 TCP 对等端口（默认值：`4662`）。

```bash
ed2k-tool kad-publish nodes.dat D:\share --port:4662
# kad published files=3 packets=12
```

## `download <ed2k-link> [--out:PATH] [--server:server.met]`

下载文件。支持多来源：引擎从服务器收集来源，并以 raccoon 模式从所有来源并发下载，
同时执行逐分块 MD4 校验和 AICH 损坏恢复。

- `--out:PATH` — 输出文件路径（默认值：链接中的文件名，若无文件名则为 `download.bin`）。
- `--server:server.met` — 登录时使用的服务器列表。省略此选项则使用内部备用列表。

下载时会写入稀疏 `PartFile` 和与 aMule 兼容的伴随文件。普通输出路径使用
`<file>.part.met`；对于已以 `.part` 结尾的输出路径，则使用同目录下的
`<file>.part.met` 名称（`001.part` -> `001.part.met`），以便导入或导出 aMule 临时文件。
如果下载中断，重新运行相同命令即可续传：`.part.met` 中已通过 MD4 校验的分块会被
信任并跳过（无需重新计算哈希）；不完整的分块会整个重新下载。

```bash
ed2k-tool download "ed2k://|file|ubuntu.iso|...|/" --out:ubuntu.iso --server:server.met
# downloaded ubuntu.iso
```

## 退出码

- `0` — 成功。
- `1` — 运行时错误（登录失败、无来源、下载错误、数据块损坏）。消息输出到 stdout。
- `2` — 用法错误（参数不正确）。

## 环境变量

- `ED2K_LIVE=1` — 启用实时测试（参见 README）。CLI 不使用此变量。
- `ED2K_SOURCE=ip:port` — 供实时测试使用的本地 aMule 对等节点，用于直接下载 /
  SourceExchange 检查。
- `ED2K_KAD_NODES=PATH` — 供实时测试使用的 Kad 引导种子文件，用于 `LiveKad.*`。
- `ED2K_UPLOAD_FILE=PATH` 和可选的 `ED2K_UPLOAD_PORT=n` — 实时上传会话测试框架：测试会
  监听并等待真实对等节点请求该文件。
