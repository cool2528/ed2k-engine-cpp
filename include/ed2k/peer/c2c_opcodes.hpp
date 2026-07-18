#pragma once
#include <cstdint>
namespace ed2k::peer {
namespace op {
constexpr std::uint8_t HELLO             = 0x01;
// Same opcode byte as HELLO, but these are sent under OP_EMULEPROT (0xC5).
constexpr std::uint8_t EMULEINFO         = 0x01;
constexpr std::uint8_t EMULEINFOANSWER   = 0x02;
constexpr std::uint8_t HELLOANSWER       = 0x4C;
constexpr std::uint8_t SETREQFILEID      = 0x4F;
constexpr std::uint8_t FILESTATUS        = 0x50;
constexpr std::uint8_t HASHSETREQUEST    = 0x51;
constexpr std::uint8_t HASHSETANSWER     = 0x52;
constexpr std::uint8_t REQUESTFILENAME   = 0x58;
constexpr std::uint8_t REQFILENAMEANSWER = 0x59;
constexpr std::uint8_t STARTUPLOADREQ    = 0x54;
constexpr std::uint8_t ACCEPTUPLOADREQ   = 0x55;
constexpr std::uint8_t QUEUERANKING      = 0x60;
constexpr std::uint8_t REASKFILEPING     = 0x90; // eMule UDP: <HASH 16>
constexpr std::uint8_t REASKACK          = 0x91; // eMule UDP: <RANG 2>
constexpr std::uint8_t REQUESTPREVIEW    = 0x90; // eMule TCP: <HASH 16>
constexpr std::uint8_t PREVIEWANSWER     = 0x91; // eMule TCP: <HASH 16><frames u8><u32 len + bytes>*
constexpr std::uint8_t QUEUEFULL         = 0x93; // eMule UDP: null
constexpr std::uint8_t REQUESTPARTS      = 0x47;
constexpr std::uint8_t SENDINGPART       = 0x46;
constexpr std::uint8_t COMPRESSEDPART    = 0x40;
constexpr std::uint8_t ASKSHAREDFILES    = 0x4A; // eDonkey: null
constexpr std::uint8_t ASKSHAREDFILESANSWER = 0x4B; // eDonkey: count + file records
constexpr std::uint8_t FILEREQANSNOFIL   = 0x48;
constexpr std::uint8_t OUTOFPARTREQS     = 0x57;
constexpr std::uint8_t CANCELTRANSFER    = 0x56;
constexpr std::uint8_t END_OF_DOWNLOAD   = 0x49;
// AICH (aMule src/include/protocol/ed2k/Client2Client/TCP.h) -- all four opcodes under OP_EMULEPROT(0xC5)
constexpr std::uint8_t AICHREQUEST       = 0x9B;  // <HASH16><u16 part_index><HASH20 master>
constexpr std::uint8_t AICHANSWER        = 0x9C;  // <HASH16><u16 part_index><HASH20 master><V2 recovery data>
constexpr std::uint8_t AICHFILEHASHANS   = 0x9D;  // <HASH16><HASH20 aich_master>
constexpr std::uint8_t AICHFILEHASHREQ   = 0x9E;  // <HASH16>
constexpr std::uint8_t FILEDESC          = 0x61;  // eMule: rating + comment
constexpr std::uint8_t MULTIPACKET       = 0x92;  // eMule: <HASH16><subop...>
constexpr std::uint8_t MULTIPACKETANSWER = 0x93;  // eMule TCP; same byte as UDP QUEUEFULL in UDP namespace
constexpr std::uint8_t MULTIPACKET_EXT   = 0xA4;  // eMule: <HASH16><SIZE64><subop...>
constexpr std::uint8_t REQUESTSOURCES2   = 0x83;  // eMule SX2 standalone interop: <HASH16>; multipacket SX2 carries version/options
constexpr std::uint8_t ANSWERSOURCES2    = 0x84;  // eMule SX2: version + hash + sources
// large file (I64) extensions
constexpr std::uint8_t COMPRESSEDPART_I64 = 0xA1;
constexpr std::uint8_t SENDINGPART_I64  = 0xA2;
constexpr std::uint8_t REQUESTPARTS_I64 = 0xA3;
}
}
