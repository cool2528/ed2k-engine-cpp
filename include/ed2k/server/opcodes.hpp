#pragma once
#include <cstdint>
#include <string_view>
namespace ed2k::server {

// opcode（对照 aMule Client2Server/TCP.h OP_ClientToServerTCP 锁定）
namespace op {
constexpr std::uint8_t LOGINREQUEST     = 0x01;
constexpr std::uint8_t REJECT            = 0x05;
constexpr std::uint8_t GETSERVERLIST     = 0x14;
constexpr std::uint8_t OFFERFILES        = 0x15;
constexpr std::uint8_t SEARCHREQUEST     = 0x16;
constexpr std::uint8_t GETSOURCES        = 0x19;
constexpr std::uint8_t CALLBACKREQUEST   = 0x1C;
constexpr std::uint8_t SERVERLIST        = 0x32;
constexpr std::uint8_t SEARCHRESULT      = 0x33;
constexpr std::uint8_t SERVERSTATUS      = 0x34;
constexpr std::uint8_t CALLBACKREQUESTED = 0x35;
constexpr std::uint8_t SERVERMESSAGE     = 0x38;
constexpr std::uint8_t IDCHANGE          = 0x40;
constexpr std::uint8_t SERVERIDENT       = 0x41;
constexpr std::uint8_t FOUNDSOURCES      = 0x42;
constexpr std::uint8_t NONE              = 0xFF;   // pump_until 哨兵：无目标 opcode
}

// tag-ID（对照 aMule ClientTags.h / FileTags.h / ServerTags.h 锁定）
namespace tag {
constexpr std::uint8_t CT_NAME          = 0x01;
constexpr std::uint8_t CT_PORT          = 0x0F;
constexpr std::uint8_t CT_VERSION       = 0x11;
constexpr std::uint8_t CT_SERVER_FLAGS  = 0x20;
constexpr std::uint8_t FT_FILENAME      = 0x01;
constexpr std::uint8_t FT_FILESIZE      = 0x02;
constexpr std::uint8_t FT_FILETYPE      = 0x03;
constexpr std::uint8_t FT_FILEFORMAT    = 0x04;
constexpr std::uint8_t FT_AICH_FILEHASH = 0x11;
constexpr std::uint8_t FT_SOURCES       = 0x15;
constexpr std::uint8_t ST_SERVERNAME    = 0x01;
constexpr std::uint8_t ST_DESCRIPTION   = 0x0B;
}

// CT_SERVER_FLAGS 能力位（对照 aMule SRVCAP_*；与 IDCHANGE flags 同套位值）
namespace srvflag {
constexpr std::uint32_t ZLIB       = 0x0001;
constexpr std::uint32_t NEWTAGS    = 0x0008;
constexpr std::uint32_t UNICODE    = 0x0010;
constexpr std::uint32_t LARGEFILES = 0x0100;
}

// 数值元比较符（对照 aMule ED2K_SEARCH_OP_*）
namespace searchop {
constexpr std::uint8_t EQUAL         = 0;
constexpr std::uint8_t GREATER       = 1;
constexpr std::uint8_t LESS          = 2;
constexpr std::uint8_t GREATER_EQUAL = 3;
constexpr std::uint8_t LESS_EQUAL    = 4;
constexpr std::uint8_t NOTEQUAL      = 5;
}

// 文件类型（对照 eMule ED2KFTSTR_*）
enum class FileType { Any, Audio, Video, Image, Program, Document, Archive, CdImage };
inline std::string_view filetype_string(FileType t){
  switch(t){
    case FileType::Audio:    return "Audio";
    case FileType::Video:    return "Video";
    case FileType::Image:    return "Image";
    case FileType::Program:  return "Pro";
    case FileType::Document: return "Doc";
    case FileType::Archive:  return "Arc";
    case FileType::CdImage:  return "Iso";
    case FileType::Any:      break;
  }
  return "";
}
}
