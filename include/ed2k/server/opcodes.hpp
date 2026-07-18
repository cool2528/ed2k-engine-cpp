#pragma once
#include <cstdint>
#include <string_view>
namespace ed2k::server {

// Opcodes (cross-referenced with aMule Client2Server/TCP.h OP_ClientToServerTCP, byte-level locked)
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
constexpr std::uint8_t NONE              = 0xFF;   // pump_until sentinel: no target opcode
}

// Tag IDs (cross-referenced with aMule ClientTags.h / FileTags.h / ServerTags.h, byte-level locked)
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

// CT_SERVER_FLAGS capability bits (cross-ref aMule SRVCAP_*; same bit values as IDCHANGE flags)
namespace srvflag {
constexpr std::uint32_t ZLIB       = 0x0001;
constexpr std::uint32_t NEWTAGS    = 0x0008;
constexpr std::uint32_t UNICODE    = 0x0010;
constexpr std::uint32_t LARGEFILES = 0x0100;
}

// Numeric meta comparison operators (cross-ref aMule ED2K_SEARCH_OP_*)
namespace searchop {
constexpr std::uint8_t EQUAL         = 0;
constexpr std::uint8_t GREATER       = 1;
constexpr std::uint8_t LESS          = 2;
constexpr std::uint8_t GREATER_EQUAL = 3;
constexpr std::uint8_t LESS_EQUAL    = 4;
constexpr std::uint8_t NOTEQUAL      = 5;
}

// File types (cross-ref eMule ED2KFTSTR_*)
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
