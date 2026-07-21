#pragma once
#include <chrono>
#include <cstdint>
#include <variant>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/net/udp_socket.hpp"
namespace ed2k::peer {

// eMule 标准的排队保活 reask 间隔: 源把我方放入上传队列(参见 UploadQueued{rank})后,
// 应每隔此间隔向源发一次 REASKFILEPING 以维持排队位置并取得最新排名。该值是经验值
// (沿用 eMule 客户端惯例), 并非协议强制, 可按需调整; 本文件只定义常量, 定期发送的
// 循环由调用方(排队等待状态机)负责。
inline constexpr std::chrono::seconds kReaskInterval{60};

// reask_source() 单次往返的三态结果, 均为非致命结果——UDP 不可达/超时不代表下载失败,
// 调用方应退化为纯 TCP 被动等待, 而不是把该源当作错误放弃:
//   - ReaskRank:        收到 REASKACK, 对端返回了更新后的队列排名
//   - ReaskQueueFull:    收到 QUEUEFULL, 对端队列已满
//   - ReaskUnavailable:  发送失败 / 超时未响应 / 响应无法解析——本次 reask 未取得有效信息
struct ReaskRank { std::uint16_t rank; };
struct ReaskQueueFull {};
struct ReaskUnavailable {};
using ReaskOutcome = std::variant<ReaskRank, ReaskQueueFull, ReaskUnavailable>;

// 向 source(源在 mule-info 握手中通告的 UDP 端点, 见 download.cpp 的 source_udp_port())
// 发送一次 REASKFILEPING(file_hash), 等待其 REASKACK(rank)/QUEUEFULL 响应或超时。
//
// sock 是调用方持有的共享 UdpSocket——按设计, 所有下载共用同一个实例(不 per-peer 各建
// 一个 socket)。这意味着 sock 上可能同时有其它源的 reask 流量往来; 本函数按发送方
// endpoint 过滤, 只接受来自 source 的响应, 其它发送方的流量丢弃后继续等待, 直到超时
// (不会因为无关流量而提前放弃本次等待预算)。
//
// 并发限制(调用方必须遵守): net::UdpSocket::recv_datagram 直接对底层 asio socket
// 发起单次 async_receive_from, 不做多路调度/仲裁(与 UdpServerConnection 的既有
// "not safe for concurrent calls" 限制同源)。若两个 reask_source 调用在同一个 sock
// 实例上并发挂起等待(例如两个源恰好同时到达各自的保活间隔), 二者的 recv 会对同一
// socket 产生并发的 outstanding 读操作——这不是 asio 支持的用法, 可能导致后到达的
// 响应被另一个调用"偷走"(sender 不匹配即丢弃, 而不会转发给真正等待它的调用), 使
// 原本收到了 REASKACK 的源被误判超时。本函数只负责单次调用自身的正确性(发送 + 按
// endpoint 过滤接收 + 超时); 调用方(排队等待状态机)必须保证同一个 sock 实例上任意
// 时刻只有一个 reask_source 调用在等待接收(例如用互斥量/strand 串行化多个源的 reask,
// 或引入单一读者协程解复用后按 endpoint 分发)——本函数不提供这层仲裁。
boost::asio::awaitable<ReaskOutcome>
reask_source(net::UdpSocket& sock, boost::asio::ip::udp::endpoint source,
             const FileHash& file_hash, std::chrono::milliseconds timeout);

}
