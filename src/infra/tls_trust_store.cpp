#include "infra/tls_trust_store.hpp"

#include <cstdint>
#include <fstream>
#include <limits>
#include <string>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl/verify_mode.hpp>

#include "ed2k/util/error.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509err.h>

#include <memory>
#endif

namespace ed2k::infra {
namespace asio = boost::asio;

namespace {

#ifdef _WIN32
class WindowsCertificateStore {
 public:
  explicit WindowsCertificateStore(HCERTSTORE handle) noexcept : handle_(handle) {}
  ~WindowsCertificateStore() {
    if (handle_) {
      CertCloseStore(handle_, 0);
    }
  }

  WindowsCertificateStore(const WindowsCertificateStore&) = delete;
  WindowsCertificateStore& operator=(const WindowsCertificateStore&) = delete;

  HCERTSTORE get() const noexcept { return handle_; }

 private:
  HCERTSTORE handle_ = nullptr;
};

struct X509Deleter {
  void operator()(X509* certificate) const noexcept { X509_free(certificate); }
};

bool import_windows_root_store(asio::ssl::context& context, DWORD location) {
  WindowsCertificateStore store(CertOpenStore(
    CERT_STORE_PROV_SYSTEM_W,
    0,
    0,
    location | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
    L"ROOT"));
  if (!store.get()) {
    return false;
  }

  X509_STORE* target = SSL_CTX_get_cert_store(context.native_handle());
  if (!target) {
    return false;
  }

  PCCERT_CONTEXT certificate = nullptr;
  while ((certificate = CertEnumCertificatesInStore(store.get(), certificate)) != nullptr) {
    const unsigned char* encoded = certificate->pbCertEncoded;
    std::unique_ptr<X509, X509Deleter> decoded(
      d2i_X509(nullptr, &encoded, static_cast<long>(certificate->cbCertEncoded)));
    if (!decoded) {
      ERR_clear_error();
      continue;
    }
    if (X509_STORE_add_cert(target, decoded.get()) != 1) {
      const unsigned long error = ERR_peek_last_error();
      const bool duplicate = error != 0 && ERR_GET_LIB(error) == ERR_LIB_X509 &&
                             ERR_GET_REASON(error) == X509_R_CERT_ALREADY_IN_HASH_TABLE;
      ERR_clear_error();
      if (!duplicate) {
        return false;
      }
    }
  }

  const DWORD enumeration_error = GetLastError();
  return enumeration_error == CRYPT_E_NOT_FOUND;
}
#endif

std::error_code add_certificate_authority(asio::ssl::context& context,
                                          const std::filesystem::path& path) {
  std::error_code filesystem_error;
  const auto status = std::filesystem::status(path, filesystem_error);
  if (filesystem_error) {
    return make_error_code(filesystem_error == std::errc::no_such_file_or_directory
                             ? errc::file_not_found
                             : errc::io_error);
  }
  if (!std::filesystem::exists(status)) {
    return make_error_code(errc::file_not_found);
  }
  if (!std::filesystem::is_regular_file(status)) {
    return make_error_code(errc::io_error);
  }

  std::ifstream input(path, std::ios::binary);
  if (!input) {
    return make_error_code(errc::io_error);
  }

  const auto certificate_size = std::filesystem::file_size(path, filesystem_error);
  if (filesystem_error) {
    return make_error_code(errc::io_error);
  }
  if (certificate_size == 0) {
    return make_error_code(errc::tls_error);
  }
  if (certificate_size >
        static_cast<std::uintmax_t>(std::numeric_limits<std::streamsize>::max()) ||
      certificate_size > static_cast<std::uintmax_t>(std::string{}.max_size())) {
    return make_error_code(errc::io_error);
  }

  std::string certificate(static_cast<std::size_t>(certificate_size), '\0');
  input.read(certificate.data(), static_cast<std::streamsize>(certificate.size()));
  if (!input || input.gcount() != static_cast<std::streamsize>(certificate.size())) {
    return make_error_code(errc::io_error);
  }

  boost::system::error_code error;
  context.add_certificate_authority(asio::buffer(certificate), error);
  return error ? make_error_code(errc::tls_error) : std::error_code{};
}

} // namespace

tl::expected<std::unique_ptr<asio::ssl::context>, std::error_code>
create_tls_client_context(
  const std::optional<std::filesystem::path>& additional_ca_file) {
  try {
    auto context = std::make_unique<asio::ssl::context>(asio::ssl::context::tls_client);
    context->set_verify_mode(asio::ssl::verify_peer);

    boost::system::error_code default_paths_error;
    context->set_default_verify_paths(default_paths_error);
#ifdef _WIN32
    const bool imported_current_user =
      import_windows_root_store(*context, CERT_SYSTEM_STORE_CURRENT_USER);
    const bool imported_local_machine =
      import_windows_root_store(*context, CERT_SYSTEM_STORE_LOCAL_MACHINE);
    if (!imported_current_user || !imported_local_machine) {
      return tl::unexpected(make_error_code(errc::tls_error));
    }
#else
    if (default_paths_error) {
      return tl::unexpected(make_error_code(errc::tls_error));
    }
#endif

    if (additional_ca_file) {
      const auto additional_ca_error = add_certificate_authority(*context, *additional_ca_file);
      if (additional_ca_error) {
        return tl::unexpected(additional_ca_error);
      }
    }
    return context;
  } catch (const std::exception&) {
    return tl::unexpected(make_error_code(errc::tls_error));
  }
}

} // namespace ed2k::infra
