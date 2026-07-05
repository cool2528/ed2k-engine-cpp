#pragma once
#include <cstdint>
namespace ed2k::server {
namespace udpop {
constexpr std::uint8_t GLOBSEARCHREQ2    = 0x92;
constexpr std::uint8_t GLOBSEARCHRES     = 0x99;
constexpr std::uint8_t GLOBGETSOURCES2   = 0x94;
constexpr std::uint8_t GLOBFOUNDSOURCES2 = 0x95;
constexpr std::uint8_t GLOBFOUNDSOURCES  = 0x9B;
constexpr std::uint8_t GLOBSERVSTATREQ   = 0x96;
constexpr std::uint8_t GLOBSERVSTATRES   = 0x97;
constexpr std::uint8_t SERVER_LIST_REQ   = 0xA0;
constexpr std::uint8_t SERVER_LIST_RES   = 0xA1;
constexpr std::uint8_t SERVER_DESC_REQ   = 0xA2;
constexpr std::uint8_t SERVER_DESC_RES   = 0xA3;
constexpr std::uint8_t SERVER_IDENT      = 0x56;
constexpr std::uint8_t INVALID_LOWID     = 0x9E;
}
namespace udpflag {
constexpr std::uint32_t EXT_GETSOURCES  = 0x00000001;
constexpr std::uint32_t EXT_GETFILES    = 0x00000002;
constexpr std::uint32_t NEWTAGS         = 0x00000008;
constexpr std::uint32_t UNICODE         = 0x00000010;
constexpr std::uint32_t EXT_GETSOURCES2 = 0x00000020;
constexpr std::uint32_t LARGEFILES      = 0x00000100;
constexpr std::uint32_t UDPOBFUSCATION  = 0x00000200;
constexpr std::uint32_t TCPOBFUSCATION  = 0x00000400;
}
constexpr std::uint16_t INV_SERV_DESC_LEN = 0xF0FF;   // SERVER_DESC_RES 新格式判定值
}
