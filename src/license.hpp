// Signed license files. The vendor signs the body with an Ed25519 private key
// (tools/fw-license); the device embeds/loads only the public key and verifies
// with OpenSSL's EVP_DigestVerify -- no hand-rolled crypto.
//
//   customer=Acme
//   license-id=L-0001
//   device-id=3f9a...        (or "*" for a site license)
//   features=url-filtering,api
//   issued=1760000000        (unix seconds)
//   expires=1790000000
//   grace-days=14
//   signature=<base64 Ed25519 over every byte above this line>
#pragma once
#include <cstdint>
#include <optional>
#include <set>
#include <string>

namespace fw {

struct License {
  std::string customer, license_id, device_id;
  std::set<std::string> features;
  int64_t issued = 0, expires = 0, grace_days = 0;
};

// Parses and verifies. Fields are only returned if the signature is valid.
// pubkey_pem: Ed25519 public key in PEM. On failure returns nullopt + err.
std::optional<License> parse_and_verify_license(const std::string& text, const std::string& pubkey_pem, std::string* err);
// The field parser alone (body = everything above the signature line). Only
// ever called on authenticated bytes; exposed so the fuzzer can reach it.
std::optional<License> parse_license_body(const std::string& body, std::string* err);

enum class LicState { None, Valid, Grace, Expired, Invalid };
const char* lic_state_name(LicState s);

struct LicenseStatus {
  LicState state = LicState::None;
  std::string reason;
  std::optional<License> lic;
  bool feature(const std::string& f) const {
    return (state == LicState::Valid || state == LicState::Grace) && lic && lic->features.count(f);
  }
};

// Pure policy: no I/O, so every case is unit-testable with fake clocks.
// clock_hwm: highest wall-clock time this device has ever observed.
LicenseStatus evaluate_license(const std::optional<License>& lic, int64_t now, const std::string& device_id,
                               int64_t clock_hwm);

constexpr int64_t kClockSkewTolerance = 300;  // seconds

std::string device_id_from_machine_id(const std::string& machine_id);
std::string local_device_id();  // from /etc/machine-id

// Persisted clock high-water mark; protects against "set the clock back to
// extend an expired license".
class ClockGuard {
 public:
  explicit ClockGuard(std::string path);
  int64_t observe(int64_t now);  // returns the high-water mark (before update)
  int64_t hwm() const { return hwm_; }

 private:
  std::string path_;
  int64_t hwm_ = 0, persisted_ = 0;
};

// Vendor-side helpers (also used by tests).
std::string ed25519_sign_b64(const std::string& priv_pem, const std::string& msg);
void ed25519_keygen(std::string* priv_pem, std::string* pub_pem);

}  // namespace fw
