#pragma once
#include <cstdint>
namespace ed2k::peer {
namespace op {
constexpr std::uint8_t HELLO             = 0x01;
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
constexpr std::uint8_t REQUESTPARTS      = 0x47;
constexpr std::uint8_t SENDINGPART       = 0x46;
constexpr std::uint8_t COMPRESSEDPART    = 0x40;
constexpr std::uint8_t FILEREQANSNOFIL   = 0x48;
constexpr std::uint8_t OUTOFPARTREQS     = 0x57;
constexpr std::uint8_t CANCELTRANSFER    = 0x56;
constexpr std::uint8_t END_OF_DOWNLOAD   = 0x49;
// AICH / large file (I64) extensions
constexpr std::uint8_t AICHREQUEST       = 0x61;
constexpr std::uint8_t AICHANSWER       = 0x62;
constexpr std::uint8_t REQUESTPARTS_I64 = 0x30;
constexpr std::uint8_t SENDINGPART_I64  = 0x31;
constexpr std::uint8_t COMPRESSEDPART_I64 = 0x32;
}
}
