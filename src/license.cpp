#include "license.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <charconv>
#include <memory>
#include <stdexcept>

#include "util.hpp"

namespace fw {

namespace {
struct PkeyFree { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct MdFree { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };
struct BioFree { void operator()(BIO* p) const { BIO_free(p); } };
using Pkey = std::unique_ptr<EVP_PKEY, PkeyFree>;

Pkey load_pub(const std::string& pem) {
  std::unique_ptr<BIO, BioFree> b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  return Pkey(PEM_read_bio_PUBKEY(b.get(), nullptr, nullptr, nullptr));
}
Pkey load_priv(const std::string& pem) {
  std::unique_ptr<BIO, BioFree> b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  return Pkey(PEM_read_bio_PrivateKey(b.get(), nullptr, nullptr, nullptr));
}

bool parse_i64(const std::string& s, int64_t& out) {
  if (s.empty() || s.size() > 19) return false;
  auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
  return ec == std::errc() && p == s.data() + s.size() && out >= 0;
}
}  // namespace

std::optional<License> parse_and_verify_license(const std::string& text, const std::string& pubkey_pem,
                                                std::string* err) {
  auto fail = [&](std::string m) -> std::optional<License> {
    if (err) *err = std::move(m);
    return std::nullopt;
  };
  if (text.size() > 8192) return fail("license file too large");
  // signature line must be the last line; everything before it is signed
  size_t sig = text.rfind("\nsignature=");
  if (sig == std::string::npos) return fail("missing signature");
  std::string body = text.substr(0, sig + 1);
  std::string sigline = trim(text.substr(sig + 11));
  if (sigline.find('\n') != std::string::npos) return fail("data after signature");
  auto raw = b64decode(sigline);
  if (!raw || raw->size() != 64) return fail("malformed signature");

  Pkey pub = load_pub(pubkey_pem);
  if (!pub || EVP_PKEY_get_id(pub.get()) != EVP_PKEY_ED25519) return fail("bad public key");
  std::unique_ptr<EVP_MD_CTX, MdFree> ctx(EVP_MD_CTX_new());
  // Ed25519 is "pure": no digest is passed, and the message goes in one shot
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pub.get()) != 1 ||
      EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char*>(raw->data()), raw->size(),
                       reinterpret_cast<const unsigned char*>(body.data()), body.size()) != 1)
    return fail("signature verification failed");
  // only now interpret the (authenticated) body, still strictly
  return parse_license_body(body, err);
}

std::optional<License> parse_license_body(const std::string& body, std::string* err) {
  auto fail = [&](std::string m) -> std::optional<License> {
    if (err) *err = std::move(m);
    return std::nullopt;
  };
  License l;
  std::set<std::string> seen;
  size_t pos = 0;
  while (pos < body.size()) {
    // npos + 1 == 0 would restart the loop forever on a last line without '\n'
    // (found by fuzz_license: input "#"; see fuzz/regressions/)
    size_t nl = body.find('\n', pos);
    if (nl == std::string::npos) nl = body.size();
    std::string line = body.substr(pos, nl - pos);
    pos = nl + 1;
    if (line.empty() || line[0] == '#') continue;
    auto eq = line.find('=');
    if (eq == std::string::npos) return fail("malformed line");
    std::string k = line.substr(0, eq), v = line.substr(eq + 1);
    if (!seen.insert(k).second) return fail("duplicate field " + k);
    if (k == "customer") l.customer = v;
    else if (k == "license-id") l.license_id = v;
    else if (k == "device-id") l.device_id = v;
    else if (k == "features") {
      size_t a = 0;
      while (a <= v.size()) {
        size_t c = v.find(',', a);
        if (c == std::string::npos) c = v.size();
        if (c > a) l.features.insert(v.substr(a, c - a));
        a = c + 1;
      }
    } else if (k == "issued") {
      if (!parse_i64(v, l.issued)) return fail("bad issued");
    } else if (k == "expires") {
      if (!parse_i64(v, l.expires)) return fail("bad expires");
    } else if (k == "grace-days") {
      if (!parse_i64(v, l.grace_days) || l.grace_days > 365) return fail("bad grace-days");
    } else {
      return fail("unknown field " + k);
    }
  }
  for (const char* req : {"license-id", "device-id", "issued", "expires"})
    if (!seen.count(req)) return fail(std::string("missing field ") + req);
  if (l.expires <= l.issued) return fail("expires before issued");
  return l;
}

const char* lic_state_name(LicState s) {
  switch (s) {
    case LicState::None: return "none";
    case LicState::Valid: return "valid";
    case LicState::Grace: return "grace";
    case LicState::Expired: return "expired";
    case LicState::Invalid: return "invalid";
  }
  return "?";
}

LicenseStatus evaluate_license(const std::optional<License>& lic, int64_t now, const std::string& device_id,
                               int64_t clock_hwm) {
  LicenseStatus st;
  st.lic = lic;
  if (!lic) {
    st.state = LicState::None;
    st.reason = "no license installed";
    return st;
  }
  if (lic->device_id != "*" && lic->device_id != device_id) {
    st.state = LicState::Invalid;
    st.reason = "license is bound to device " + lic->device_id + ", this device is " + device_id;
    return st;
  }
  // clock rollback: the wall clock is behind a time we have already seen, or
  // behind the license's own issue date
  if (clock_hwm > 0 && now + kClockSkewTolerance < clock_hwm) {
    st.state = LicState::Invalid;
    st.reason = "system clock moved backwards by " + std::to_string(clock_hwm - now) + "s";
    return st;
  }
  if (now + kClockSkewTolerance < lic->issued) {
    st.state = LicState::Invalid;
    st.reason = "system clock is before the license issue date";
    return st;
  }
  if (now < lic->expires) {
    st.state = LicState::Valid;
    st.reason = "expires in " + std::to_string((lic->expires - now) / 86400) + " days";
    return st;
  }
  int64_t grace_end = lic->expires + lic->grace_days * 86400;
  if (now < grace_end) {
    st.state = LicState::Grace;
    st.reason = "expired; grace period ends in " + std::to_string((grace_end - now + 3599) / 3600) + " hours";
    return st;
  }
  st.state = LicState::Expired;
  st.reason = "expired and grace period over";
  return st;
}

std::string device_id_from_machine_id(const std::string& machine_id) {
  return sha256_hex("fw-mgmtd-device:" + trim(machine_id)).substr(0, 16);
}

std::string local_device_id() {
  auto m = read_file("/etc/machine-id");
  return device_id_from_machine_id(m.value_or("unknown"));
}

ClockGuard::ClockGuard(std::string path) : path_(std::move(path)) {
  if (auto t = read_file(path_)) {
    int64_t v;
    std::string s = trim(*t);
    if (parse_i64(s, v)) hwm_ = persisted_ = v;
  }
}

int64_t ClockGuard::observe(int64_t now) {
  int64_t before = hwm_;
  if (now > hwm_) {
    hwm_ = now;
    // persist at most once a minute so a running device doesn't thrash the disk
    if (hwm_ - persisted_ >= 60 || persisted_ == 0) {
      atomic_write(path_, std::to_string(hwm_) + "\n");
      persisted_ = hwm_;
    }
  }
  return before;
}

std::string ed25519_sign_b64(const std::string& priv_pem, const std::string& msg) {
  Pkey k = load_priv(priv_pem);
  if (!k) throw std::runtime_error("bad private key");
  std::unique_ptr<EVP_MD_CTX, MdFree> ctx(EVP_MD_CTX_new());
  size_t len = 64;
  unsigned char sig[64];
  if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, k.get()) != 1 ||
      EVP_DigestSign(ctx.get(), sig, &len, reinterpret_cast<const unsigned char*>(msg.data()), msg.size()) != 1)
    throw std::runtime_error("sign failed");
  return b64encode(std::string_view(reinterpret_cast<char*>(sig), len));
}

void ed25519_keygen(std::string* priv_pem, std::string* pub_pem) {
  Pkey k(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
  if (!k) throw std::runtime_error("keygen failed");
  auto dump = [](auto fn) {
    std::unique_ptr<BIO, BioFree> b(BIO_new(BIO_s_mem()));
    fn(b.get());
    char* p;
    long n = BIO_get_mem_data(b.get(), &p);
    return std::string(p, static_cast<size_t>(n));
  };
  *priv_pem = dump([&](BIO* b) { PEM_write_bio_PrivateKey(b, k.get(), nullptr, nullptr, 0, nullptr, nullptr); });
  *pub_pem = dump([&](BIO* b) { PEM_write_bio_PUBKEY(b, k.get()); });
}

}  // namespace fw
