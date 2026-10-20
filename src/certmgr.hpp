// Certificate lifecycle for the HTTPS listener (OpenSSL 3):
//   keygen (EC P-256) -> CSR -> ACME (RFC 8555, http-01) -> install ->
//   hot-reload into the listener -> renew before expiry -> expiry alerts,
//   plus OCSP and CRL revocation checks.
#pragma once
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "http.hpp"
#include "store.hpp"

namespace fw {

class Syslog;

std::string gen_ec_key_pem();
std::string make_csr_der(const std::string& key_pem, const std::string& cn);
std::string self_signed_pem(const std::string& key_pem, const std::string& cn, int days);

struct CertInfo {
  std::string subject, issuer, serial, sans;
  int64_t not_before = 0, not_after = 0;
  bool ok = false;
};
CertInfo cert_info(const std::string& cert_pem);

struct RevocationResult {
  std::string method;  // "ocsp" / "crl"
  std::string status;  // "good" / "revoked" / "unknown" / "error"
  std::string detail;
};
// Checks the leaf against every OCSP responder (AIA) and CRL distribution
// point it names. issuer_pem verifies the CRL / OCSP response signature.
std::vector<RevocationResult> check_revocation(const std::string& cert_pem, const std::string& issuer_pem);

struct AcmeResult {
  bool ok = false;
  std::string error, cert_chain_pem;
  double ms = 0;
};
// Full RFC 8555 flow against e.g. Pebble. Serves the http-01 token itself on
// challenge_port for the duration of the order.
AcmeResult acme_issue(const std::string& directory_url, const std::string& ca_file, const std::string& cn,
                      const std::string& key_pem, int challenge_port, const std::string& account_key_path);

class CertManager : public Subscriber {
 public:
  static constexpr int64_t kActivationMarginS = 2;  // seconds past notBefore before a cert goes live
  using Reload = std::function<void(SslCtxPtr)>;
  CertManager(std::string dir, Syslog* log, Reload reload, std::string acme_ca, int challenge_port);

  void start_with_existing_or_selfsigned();
  // Renew now via ACME (or self-signed if no ACME directory configured).
  AcmeResult renew(const std::string& why);
  void tick();  // timer: renewal + alerts
  std::string show() const;
  std::vector<RevocationResult> check_revocation_now();
  int64_t seconds_left() const;

  std::string name() const override { return "certificate"; }
  std::vector<std::string> prefixes() const override { return {"system certificate", "system hostname"}; }
  void apply(const Config& c, const std::vector<Change>&) override;

 private:
  void install(const std::string& key, const std::string& chain, const std::string& source);

  std::string dir_;
  Syslog* log_;
  Reload reload_;
  std::string acme_ca_;
  int chal_port_;
  mutable std::mutex mu_, renew_mu_;
  std::string cn_ = "localhost", directory_;
  int64_t renew_before_ = 30 * 86400;
  int alert_days_ = 14;
  std::string cert_pem_, source_;
  CertInfo info_;
  int renewals_ = 0, failures_ = 0;
  int64_t last_alert_bucket_ = -1;
  std::string last_error_;
  double last_ms_ = 0;
};

}  // namespace fw
