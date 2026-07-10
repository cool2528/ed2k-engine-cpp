#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <system_error>

#include <boost/asio/ssl/context.hpp>
#include <tl/expected.hpp>

namespace ed2k::infra {

tl::expected<std::unique_ptr<boost::asio::ssl::context>, std::error_code>
create_tls_client_context(
  const std::optional<std::filesystem::path>& additional_ca_file);

} // namespace ed2k::infra
