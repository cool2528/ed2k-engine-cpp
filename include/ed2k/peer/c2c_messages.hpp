#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <array>
#include <utility>
#include <vector>
#include <tl/expected.hpp>
#include "ed2k/core/hash.hpp"
#include "ed2k/peer/c2c_opcodes.hpp"
#include "ed2k/server/opcodes.hpp"   // tag::CT_NAME/CT_VERSION
namespace ed2k::peer {

struct HelloInfo {
  UserHash user_hash;
  std::uint32_t client_id = 0;
  std::uint16_t port = 0;
  std::string nickname;
  std::uint32_t version = 0x3C;
  std::optional<IPv4> server_ip;
  std::optional<std::uint16_t> server_port;
};

// C→C 编码：返回 payload（opcode 由调用方设入 net::Packet）
// aMule 线格式(BYTE-COMPARE 锁定自 BaseClient.cpp SendHelloPacket/SendHelloAnswer/SendHelloTypePacket):
//   - OP_HELLO     payload = [0x10 hashsize][hash:16][client_id:4][port:2][tagcount:4][tags][server_ip:4 BE][server_port:2]
//   - OP_HELLOANSWER payload = [hash:16][client_id:4][port:2][tagcount:4][tags][server_ip:4 BE][server_port:2]   (无 0x10 前导)
// 即 HELLO 比 HELLOANSWER 多一个 0x10 前导字节；二者 body 末尾均含 server_ip+server_port(0/0 若未连服务器)。
// 发 OP_HELLO 用 encode_hello_packet；发 OP_HELLOANSWER 用 encode_hello。解码同理(decode_hello / decode_hello_answer)。
std::vector<std::byte> encode_hello(const HelloInfo&);          // HELLOANSWER body(无 0x10 前导)/HELLO body
std::vector<std::byte> encode_hello_packet(const HelloInfo&);   // OP_HELLO payload = [0x10] + encode_hello(h)
std::vector<std::byte> encode_set_req_file(const FileHash&);
std::vector<std::byte> encode_hashset_request(const FileHash&);
std::vector<std::byte> encode_request_filename(const FileHash&);
std::vector<std::byte> encode_start_upload(const FileHash&);
std::vector<std::byte> encode_request_parts(const FileHash&, std::array<std::uint32_t,3> starts, std::array<std::uint32_t,3> ends);
std::vector<std::byte> encode_end_of_download(const FileHash&);
std::vector<std::byte> encode_cancel_transfer();

// S→C 结构
struct FileStatus { FileHash hash; std::vector<bool> parts; };
struct FileNameAnswer { FileHash hash; std::string name; };
struct Block { FileHash hash; std::uint64_t start=0, end=0; std::vector<std::byte> data; };

tl::expected<HelloInfo,std::error_code>          decode_hello(std::span<const std::byte>);        // OP_HELLO(校验并跳过 0x10 前导)
tl::expected<HelloInfo,std::error_code>          decode_hello_answer(std::span<const std::byte>); // OP_HELLOANSWER(无前导)
tl::expected<FileStatus,std::error_code>         decode_file_status(std::span<const std::byte>);
tl::expected<std::vector<PartHash>,std::error_code> decode_hashset_answer(const FileHash& expected, std::span<const std::byte>);
tl::expected<FileNameAnswer,std::error_code>     decode_req_filename_answer(std::span<const std::byte>);
tl::expected<std::uint16_t,std::error_code>      decode_queue_ranking(std::span<const std::byte>);
tl::expected<Block,std::error_code>              decode_sending_part(std::span<const std::byte>);
tl::expected<Block,std::error_code>              decode_compressed_part(std::span<const std::byte>);
tl::expected<FileHash,std::error_code>           decode_file_req_ans_no_fil(std::span<const std::byte>);

// AICH (aMule SHAHashSet) — 两级 Merkle 树恢复数据。详见 aich_checker.hpp / 设计 spec §5。
// 四个 opcode 均在 OP_EMULEPROT(0xC5) 下，非 eDonkey(0xE3)。
struct AICHProofHash {
  std::uint32_t identifier;                 // 16-bit 标识符高位补零到 32-bit (aMule ReCalculateHash 路径)
  std::array<std::byte, 20> hash;
};
struct AICHRecoveryData {
  std::vector<AICHProofHash> hashes;        // V2 recovery data: 16-bit + 32-bit 标识符 hash 列表
};

// OP_AICHFILEHASHREQ(0x9E) -> OP_AICHFILEHASHANS(0x9D): 交换文件 AICH master hash (根)
std::vector<std::byte> encode_aich_file_hash_req(const FileHash&);
tl::expected<AICHHash, std::error_code> decode_aich_file_hash_ans(std::span<const std::byte>);

// OP_AICHREQUEST(0x9B) -> OP_AICHANSWER(0x9C): 请求/返回某 part 的 V2 恢复数据
//   请求帧 = file_hash(16) + part_index(u16) + master_hash(20) = 38B (aMule SendAICHRequest 顺序)
//   应答帧 = file_hash(16) + part_index(u16) + master_hash(20) + V2 recovery data
std::vector<std::byte> encode_aich_request(const FileHash&, const AICHHash& master, std::uint16_t part_index);
tl::expected<AICHRecoveryData, std::error_code> decode_aich_answer(std::span<const std::byte>);

// I64 (large file >4GiB) messages
std::vector<std::byte> encode_request_parts_i64(const FileHash&, std::array<std::uint64_t,3> starts, std::array<std::uint64_t,3> ends);
tl::expected<Block,std::error_code>              decode_sending_part_i64(std::span<const std::byte>);
tl::expected<Block,std::error_code>              decode_compressed_part_i64(std::span<const std::byte>);
}
