#include "infra/tls_trust_store.hpp"

#include <fstream>
#include <iterator>
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

bool import_windows_root_store(asio::ssl::context& context) {
  WindowsCertificateStore store(CertOpenSystemStoreW(HCRYPTPROV_LEGACY{}, L"ROOT"));
  if (!store.get()) {
    return false;
  }

  X509_STORE* target = SSL_CTX_get_cert_store(context.native_handle());
  if (!target) {
    return false;
  }

  bool imported = false;
  PCCERT_CONTEXT certificate = nullptr;
  while ((certificate = CertEnumCertificatesInStore(store.get(), certificate)) != nullptr) {
    const unsigned char* encoded = certificate->pbCertEncoded;
    std::unique_ptr<X509, X509Deleter> decoded(
      d2i_X509(nullptr, &encoded, static_cast<long>(certificate->cbCertEncoded)));
    if (!decoded) {
      ERR_clear_error();
      continue;
    }
    if (X509_STORE_add_cert(target, decoded.get()) == 1) {
      imported = true;
    } else {
      // Duplicate or unsupported roots only narrow trust; they must not disable verification.
      ERR_clear_error();
    }
  }

  return imported && GetLastError() == CRYPT_E_NOT_FOUND;
}
#endif

bool add_certificate_authority(asio::ssl::context& context,
                               const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    return false;
  }
  const std::string certificate((std::istreambuf_iterator<char>(input)),
                                std::istreambuf_iterator<char>());
  if (certificate.empty() || !input.eof()) {
    return false;
  }

  boost::system::error_code error;
  context.add_certificate_authority(asio::buffer(certificate), error);
  return !error;
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
    if (!import_windows_root_store(*context)) {
      return tl::unexpected(make_error_code(errc::tls_error));
    }
#else
    if (default_paths_error) {
      return tl::unexpected(make_error_code(errc::tls_error));
    }
#endif

    if (additional_ca_file && !add_certificate_authority(*context, *additional_ca_file)) {
      return tl::unexpected(make_error_code(errc::tls_error));
    }
    return context;
  } catch (const std::exception&) {
    return tl::unexpected(make_error_code(errc::tls_error));
  }
}

} // namespace ed2k::infra
