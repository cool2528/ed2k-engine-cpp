#include "ed2k/peer/peer_reask.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/peer/c2c_opcodes.hpp"
#include "ed2k/net/udp_framing.hpp"
#include <chrono>
#include <utility>
namespace ed2k::peer {
namespace asio = boost::asio;
using udp = asio::ip::udp;
using clock_type = std::chrono::steady_clock;

asio::awaitable<ReaskOutcome>
reask_source(net::UdpSocket& sock, udp::endpoint source, const FileHash& file_hash,
             std::chrono::milliseconds timeout){
  // REASKFILEPING/REASKACK/QUEUEFULL 都是 eMule 扩展 opcode(>=0x90), 走 OP_EMULEPROT(0xC5)——
  // 与既有 TCP 侧 c2c_connection.cpp 对 >=0x90 系列 opcode(AICH/MULTIPACKET/SOURCEEXCHANGE2 等)
  // 的协议标记约定一致。
  net::Packet req;
  req.protocol = net::proto::eMule;
  req.opcode = op::REASKFILEPING;
  req.payload = encode_reask_file_ping(file_hash);
  auto sent = co_await sock.send_to(source, req);
  if(!sent) co_return ReaskOutcome{ReaskUnavailable{}};   // 发送失败(网络不可达等): 非致命

  const auto deadline = clock_type::now() + timeout;
  while(true){
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock_type::now());
    if(remaining.count() <= 0) co_return ReaskOutcome{ReaskUnavailable{}};   // 超时: 非致命
    auto rp = co_await sock.recv_datagram(remaining);
    if(!rp) co_return ReaskOutcome{ReaskUnavailable{}};   // recv 超时/socket 出错: 非致命
    auto [datagram, sender] = std::move(*rp);
    if(sender != source) continue;   // 共享 socket 上其它源的流量, 丢弃继续等(不消耗判定结果)
    auto parsed = net::parse_udp_datagram(datagram);
    if(!parsed) co_return ReaskOutcome{ReaskUnavailable{}};   // 目标源发来但无法解析: 非致命放弃
    auto pkt = std::move(*parsed);
    if(pkt.protocol != net::proto::eMule) continue;   // 目标源发来但协议标记不对: 忽略继续等
    if(pkt.opcode == op::QUEUEFULL) co_return ReaskOutcome{ReaskQueueFull{}};
    if(pkt.opcode == op::REASKACK){
      auto rank = decode_queue_ranking(pkt.payload);
      if(!rank) co_return ReaskOutcome{ReaskUnavailable{}};   // 载荷畸形: 非致命放弃
      co_return ReaskOutcome{ReaskRank{*rank}};
    }
    continue;   // 目标源发来的其它 opcode: 忽略继续等
  }
}
}
