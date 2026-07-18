#pragma once
// Umbrella header: complete public API.
// Pulls in all submodules — prefer targeted includes for faster builds.

// Version
#include "ed2k/version.hpp"

// Core types
#include "ed2k/core/hash.hpp"
#include "ed2k/util/error.hpp"
#include "ed2k/util/log.hpp"
#include "ed2k/codec/byte_io.hpp"
#include "ed2k/codec/tag.hpp"

// Hashing
#include "ed2k/hash/ed2k_hasher.hpp"
#include "ed2k/hash/aich_hasher.hpp"

// Link parsing
#include "ed2k/link/ed2k_link.hpp"

// Metadata files
#include "ed2k/metfile/server_met.hpp"
#include "ed2k/metfile/known_part_met.hpp"

// Crypto
#include "ed2k/crypto/md5.hpp"
#include "ed2k/crypto/rc4.hpp"
#include "ed2k/crypto/sha1.hpp"

// Network
#include "ed2k/net/runtime.hpp"
#include "ed2k/net/connection.hpp"
#include "ed2k/net/packet.hpp"
#include "ed2k/net/framing.hpp"
#include "ed2k/net/udp_socket.hpp"
#include "ed2k/net/udp_framing.hpp"
#include "ed2k/net/udp_obfuscation.hpp"
#include "ed2k/net/encrypted_stream_socket.hpp"

// Server protocol
#include "ed2k/server/connection.hpp"
#include "ed2k/server/messages.hpp"
#include "ed2k/server/search_query.hpp"
#include "ed2k/server/udp_connection.hpp"
#include "ed2k/server/udp_messages.hpp"

// Peer protocol
#include "ed2k/peer/c2c_connection.hpp"
#include "ed2k/peer/c2c_messages.hpp"
#include "ed2k/peer/inbound_listener.hpp"

// Download engine
#include "ed2k/download/download.hpp"
#include "ed2k/download/part_file.hpp"
#include "ed2k/download/block_allocator.hpp"
#include "ed2k/download/aich_checker.hpp"

// Upload / sharing
#include "ed2k/share/known_file.hpp"
#include "ed2k/share/upload_session.hpp"
#include "ed2k/share/upload_queue.hpp"
#include "ed2k/share/upload_throttler.hpp"
#include "ed2k/share/client_credits.hpp"

// Kademlia
#include "ed2k/kad/network.hpp"
#include "ed2k/kad/kad_id.hpp"
#include "ed2k/kad/routing_table.hpp"
#include "ed2k/kad/nodes_dat.hpp"

// Client infrastructure
#include "ed2k/infra/preferences.hpp"
#include "ed2k/infra/ip_filter.hpp"
#include "ed2k/infra/statistics.hpp"
#include "ed2k/infra/category.hpp"
#include "ed2k/infra/friend_list.hpp"
#include "ed2k/infra/client_list.hpp"
#include "ed2k/infra/proxy.hpp"
#include "ed2k/infra/http_download.hpp"
#include "ed2k/infra/collection.hpp"
#include "ed2k/infra/scheduler.hpp"
#include "ed2k/infra/chat_relay.hpp"

// High-level session orchestration
#include "ed2k/app/server_session.hpp"
