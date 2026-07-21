#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
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
  bool supports_obfuscation = false;
  bool requests_obfuscation = false;
  bool requires_obfuscation = false;
  bool supports_aich = false;
  bool supports_compression = true;
  std::uint32_t source_exchange_version = 0;
  bool supports_comments = false;
  bool supports_multipacket = false;
  bool supports_source_exchange2 = false;
  bool supports_ext_multipacket = false;
  bool supports_large_files = false;
};

enum class ClientSoftware : std::uint32_t {
  EMule = 0,
  AMule = 3,
  Lphant = 0x14,
  Unknown = 0x36,
};

struct MuleInfo {
  std::uint8_t version = 0x3C;
  std::uint8_t protocol_version = 0x01;
  bool compression = true;
  std::uint32_t udp_version = 4;
  std::uint16_t udp_port = 0;
  std::uint32_t source_exchange_version = 3;
  bool comments = true;
  std::uint32_t extended_requests_version = 2;
  std::uint32_t features = 0x03;
  std::uint32_t compatible_client = static_cast<std::uint32_t>(ClientSoftware::AMule);
  std::string mod_version;
  std::string os_info;

  ClientSoftware client_software() const;
  bool supports_obfuscation() const { return (features & 0x03u) != 0; }
  bool supports_preview() const { return (features & 0x80u) != 0; }
};

// C2C encoding: returns payload (caller sets opcode on net::Packet)
// aMule wire format (BYTE-COMPARE locked from BaseClient.cpp SendHelloPacket/SendHelloAnswer/SendHelloTypePacket):
//   - OP_HELLO     payload = [0x10 hashsize][hash:16][client_id:4][port:2][tagcount:4][tags][server_ip:4 BE][server_port:2]
//   - OP_HELLOANSWER payload = [hash:16][client_id:4][port:2][tagcount:4][tags][server_ip:4 BE][server_port:2]   (no 0x10 prefix)
// HELLO has one extra 0x10 prefix byte compared to HELLOANSWER; both bodies end with server_ip+server_port (0/0 if not connected).
// Send OP_HELLO via encode_hello_packet; send OP_HELLOANSWER via encode_hello. Decode likewise (decode_hello / decode_hello_answer).
std::vector<std::byte> encode_hello(const HelloInfo&);          // HELLOANSWER body (no 0x10 prefix) / HELLO body
std::vector<std::byte> encode_hello_packet(const HelloInfo&);   // OP_HELLO payload = [0x10] + encode_hello(h)
std::vector<std::byte> encode_mule_info(const MuleInfo&);
std::vector<std::byte> encode_set_req_file(const FileHash&);
std::vector<std::byte> encode_hashset_request(const FileHash&);
std::vector<std::byte> encode_request_filename(const FileHash&);
tl::expected<FileHash,std::error_code> decode_file_hash_request(std::span<const std::byte>);
std::vector<std::byte> encode_req_filename_answer(const FileHash&, std::string_view name);
std::vector<std::byte> encode_file_status(const FileHash&, std::span<const bool> parts);
std::vector<std::byte> encode_hashset_answer(const FileHash&, std::span<const PartHash> part_hashes);
std::vector<std::byte> encode_start_upload(const FileHash&);
std::vector<std::byte> encode_queue_ranking(std::uint16_t rank);
std::vector<std::byte> encode_reask_file_ping(const FileHash&);
std::vector<std::byte> encode_reask_ack(std::uint16_t rank);
std::vector<std::byte> encode_request_parts(const FileHash&, std::array<std::uint32_t,3> starts, std::array<std::uint32_t,3> ends);
struct RequestParts { FileHash hash; std::array<std::uint64_t,3> starts{}, ends{}; };
tl::expected<RequestParts,std::error_code> decode_request_parts(std::span<const std::byte>);
std::vector<std::byte> encode_sending_part(const FileHash&, std::uint64_t start, std::span<const std::byte> data);
std::vector<std::byte> encode_compressed_part(const FileHash&, std::uint64_t start, std::span<const std::byte> data);
std::vector<std::byte> encode_end_of_download(const FileHash&);
std::vector<std::byte> encode_cancel_transfer();

// S2C structures
struct FileStatus { FileHash hash; std::vector<bool> parts; };
struct FileNameAnswer { FileHash hash; std::string name; };
struct Block { FileHash hash; std::uint64_t start=0, end=0; std::vector<std::byte> data; };
struct SharedFileEntry { FileHash hash; std::uint32_t client_id=0; std::uint16_t port=0; };
struct PeerSource {
  std::uint32_t client_id=0;
  std::uint16_t port=0;
  std::uint32_t server_ip=0;
  std::uint16_t server_port=0;
  UserHash user_hash;
  std::uint8_t crypt_options=0;
  auto operator<=>(const PeerSource&) const = default;
};
struct SourceExchangeAnswer { std::uint8_t version=0; FileHash hash; std::vector<PeerSource> sources; };
struct FileDesc { std::uint8_t rating=0; std::string comment; };
struct PreviewAnswer { FileHash hash; std::vector<std::vector<std::byte>> frames; };
struct CompressedPartSegment {
  FileHash hash;
  std::uint64_t start = 0;
  std::uint32_t compressed_size = 0;
  std::vector<std::byte> data;
};

tl::expected<HelloInfo,std::error_code>          decode_hello(std::span<const std::byte>);        // OP_HELLO (validates and skips 0x10 prefix)
tl::expected<HelloInfo,std::error_code>          decode_hello_answer(std::span<const std::byte>); // OP_HELLOANSWER (no prefix)
tl::expected<MuleInfo,std::error_code>           decode_mule_info(std::span<const std::byte>);
tl::expected<FileStatus,std::error_code>         decode_file_status(std::span<const std::byte>);
tl::expected<std::vector<PartHash>,std::error_code> decode_hashset_answer(const FileHash& expected, std::span<const std::byte>);
tl::expected<FileNameAnswer,std::error_code>     decode_req_filename_answer(std::span<const std::byte>);
tl::expected<std::uint16_t,std::error_code>      decode_queue_ranking(std::span<const std::byte>);
// UDP REASKFILEPING(0x90) payload = 裸 16 字节文件 hash,与 decode_file_hash_request 逐位相同。
// QUEUEFULL(0x93) 无 body,不需要解码函数——UDP 分发处直接比较 datagram.opcode == op::QUEUEFULL 即可
// (与既有 pkt.opcode == op::QUEUERANKING 判定同一模式,见 c2c_connection.cpp)。
tl::expected<FileHash,std::error_code>           decode_reask_file_ping(std::span<const std::byte>);
tl::expected<Block,std::error_code>              decode_sending_part(std::span<const std::byte>);
tl::expected<CompressedPartSegment,std::error_code> decode_compressed_part_segment(std::span<const std::byte>);
tl::expected<Block,std::error_code>              inflate_compressed_part_segment(const CompressedPartSegment&);
tl::expected<Block,std::error_code>              decode_compressed_part(std::span<const std::byte>);
tl::expected<FileHash,std::error_code>           decode_file_req_ans_no_fil(std::span<const std::byte>);
std::vector<std::byte> encode_shared_files_answer(std::span<const SharedFileEntry> files);
tl::expected<std::vector<SharedFileEntry>, std::error_code> decode_shared_files_answer(std::span<const std::byte>);
std::vector<std::byte> encode_request_sources2(const FileHash&);
std::vector<std::byte> encode_multipacket_request_sources2(const FileHash&, std::uint8_t version = 4, std::uint16_t options = 0);
tl::expected<FileHash, std::error_code> decode_request_sources2(std::span<const std::byte>);
std::vector<std::byte> encode_answer_sources2(const FileHash&, std::span<const PeerSource> sources, std::uint8_t version = 4);
tl::expected<SourceExchangeAnswer, std::error_code> decode_answer_sources2(std::span<const std::byte>);
std::vector<std::byte> encode_file_desc(std::uint8_t rating, std::string_view comment);
tl::expected<FileDesc, std::error_code> decode_file_desc(std::span<const std::byte>);
std::vector<std::byte> encode_preview_request(const FileHash&);
std::vector<std::byte> encode_preview_answer(const FileHash&, std::span<const std::span<const std::byte>> frames);
tl::expected<PreviewAnswer, std::error_code> decode_preview_answer(std::span<const std::byte>);
std::vector<std::byte> encode_chat_message(std::string_view text);
tl::expected<std::string, std::error_code> decode_chat_message(std::span<const std::byte>);

// AICH (aMule SHAHashSet) -- two-level Merkle tree recovery data. See aich_checker.hpp / design spec section 5.
// All four opcodes are under OP_EMULEPROT(0xC5), not eDonkey(0xE3).
struct AICHProofHash {
  std::uint32_t identifier;                 // 16-bit identifier zero-extended to 32-bit (aMule ReCalculateHash path)
  std::array<std::byte, 20> hash;
};
struct AICHRecoveryData {
  std::vector<AICHProofHash> hashes;        // V2 recovery data: list of 16-bit + 32-bit identifier hashes
};

// OP_AICHFILEHASHREQ(0x9E) -> OP_AICHFILEHASHANS(0x9D): exchange file AICH master hash (root)
std::vector<std::byte> encode_aich_file_hash_req(const FileHash&);
std::vector<std::byte> encode_aich_file_hash_ans(const FileHash&, const AICHHash& master);
tl::expected<AICHHash, std::error_code> decode_aich_file_hash_ans(std::span<const std::byte>);
std::vector<std::byte> encode_aich_answer(const FileHash&, const AICHHash& master, std::uint16_t part_index,
                                          std::span<const AICHProofHash> proof);

// OP_AICHREQUEST(0x9B) -> OP_AICHANSWER(0x9C): request/return V2 recovery data for a part
//   Request frame = file_hash(16) + part_index(u16) + master_hash(20) = 38B (aMule SendAICHRequest order)
//   Answer frame = file_hash(16) + part_index(u16) + master_hash(20) + V2 recovery data
std::vector<std::byte> encode_aich_request(const FileHash&, const AICHHash& master, std::uint16_t part_index);
tl::expected<AICHRecoveryData, std::error_code> decode_aich_answer(std::span<const std::byte>);

// I64 (large file >4GiB) messages
std::vector<std::byte> encode_request_parts_i64(const FileHash&, std::array<std::uint64_t,3> starts, std::array<std::uint64_t,3> ends);
std::vector<std::byte> encode_compressed_part_i64(const FileHash&, std::uint64_t start, std::span<const std::byte> data);
tl::expected<Block,std::error_code>              decode_sending_part_i64(std::span<const std::byte>);
tl::expected<CompressedPartSegment,std::error_code> decode_compressed_part_i64_segment(std::span<const std::byte>);
tl::expected<Block,std::error_code>              decode_compressed_part_i64(std::span<const std::byte>);
}
