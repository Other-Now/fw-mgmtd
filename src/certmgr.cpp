#include "certmgr.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <ctime>
#include <memory>
#include <nlohmann/json.hpp>
#include <thread>

#include "syslog.hpp"
#include "util.hpp"

namespace fw {

using json = nlohmann::json;

namespace {
template <class T, void (*F)(T*)>
struct Deleter { void operator()(T* p) const { F(p); } };
using Pkey = std::unique_ptr<EVP_PKEY, Deleter<EVP_PKEY, EVP_PKEY_free>>;
using X509p = std::unique_ptr<X509, Deleter<X509, X509_free>>;
using Bio = std::unique_ptr<BIO, Deleter<BIO, BIO_free_all>>;

Pkey key_from_pem(const std::string& pem) {
  Bio b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  return Pkey(PEM_read_bio_PrivateKey(b.get(), nullptr, nullptr, nullptr));
}
X509p x509_from_pem(const std::string& pem) {
  Bio b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  return X509p(PEM_read_bio_X509(b.get(), nullptr, nullptr, nullptr));
}
std::string bio_str(BIO* b) {
  char* p;
  long n = BIO_get_mem_data(b, &p);
  return std::string(p, static_cast<size_t>(n));
}
std::string x509_pem(X509* x) {
  Bio b(BIO_new(BIO_s_mem()));
  PEM_write_bio_X509(b.get(), x);
  return bio_str(b.get());
}
int64_t asn1_to_unix(const ASN1_TIME* t) {
  struct tm tm {};
  if (!t || ASN1_TIME_to_tm(t, &tm) != 1) return 0;
  return static_cast<int64_t>(timegm(&tm));
}
void add_san(X509* x, X509_REQ* req, const std::string& cn) {
  std::string v = "DNS:" + cn;
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, x, x, req, nullptr, 0);
  X509_EXTENSION* e = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, v.c_str());
  if (x) X509_add_ext(x, e, -1);
  if (req) {
    STACK_OF(X509_EXTENSION)* st = sk_X509_EXTENSION_new_null();
    sk_X509_EXTENSION_push(st, e);
    X509_REQ_add_extensions(req, st);
    sk_X509_EXTENSION_free(st);
  }
  X509_EXTENSION_free(e);
}
}  // namespace

std::string gen_ec_key_pem() {
  Pkey k(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
  Bio b(BIO_new(BIO_s_mem()));
  PEM_write_bio_PrivateKey(b.get(), k.get(), nullptr, nullptr, 0, nullptr, nullptr);
  return bio_str(b.get());
}

std::string make_csr_der(const std::string& key_pem, const std::string& cn) {
  Pkey k = key_from_pem(key_pem);
  X509_REQ* req = X509_REQ_new();
  X509_REQ_set_version(req, X509_REQ_VERSION_1);
  X509_NAME* nm = X509_REQ_get_subject_name(req);
  X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
  add_san(nullptr, req, cn);
  X509_REQ_set_pubkey(req, k.get());
  X509_REQ_sign(req, k.get(), EVP_sha256());
  unsigned char* der = nullptr;
  int n = i2d_X509_REQ(req, &der);
  std::string out(reinterpret_cast<char*>(der), static_cast<size_t>(n));
  OPENSSL_free(der);
  X509_REQ_free(req);
  return out;
}

std::string self_signed_pem(const std::string& key_pem, const std::string& cn, int days) {
  Pkey k = key_from_pem(key_pem);
  X509p x(X509_new());
  X509_set_version(x.get(), 2);
  unsigned char ser[16];
  RAND_bytes(ser, sizeof ser);
  ser[0] &= 0x7f;
  BIGNUM* bn = BN_bin2bn(ser, sizeof ser, nullptr);
  BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x.get()));
  BN_free(bn);
  X509_gmtime_adj(X509_getm_notBefore(x.get()), -60);
  X509_gmtime_adj(X509_getm_notAfter(x.get()), static_cast<long>(days) * 86400);
  X509_NAME* nm = X509_get_subject_name(x.get());
  X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
  X509_set_issuer_name(x.get(), nm);
  X509_set_pubkey(x.get(), k.get());
  add_san(x.get(), nullptr, cn);
  X509_sign(x.get(), k.get(), EVP_sha256());
  return x509_pem(x.get());
}

CertInfo cert_info(const std::string& pem) {
  CertInfo ci;
  X509p x = x509_from_pem(pem);
  if (!x) return ci;
  char buf[512];
  X509_NAME_oneline(X509_get_subject_name(x.get()), buf, sizeof buf);
  ci.subject = buf;
  X509_NAME_oneline(X509_get_issuer_name(x.get()), buf, sizeof buf);
  ci.issuer = buf;
  BIGNUM* bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x.get()), nullptr);
  char* hex = BN_bn2hex(bn);
  ci.serial = hex;
  OPENSSL_free(hex);
  BN_free(bn);
  ci.not_before = asn1_to_unix(X509_get0_notBefore(x.get()));
  ci.not_after = asn1_to_unix(X509_get0_notAfter(x.get()));
  auto* gens = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(x.get(), NID_subject_alt_name, nullptr, nullptr));
  for (int i = 0; gens && i < sk_GENERAL_NAME_num(gens); ++i) {
    auto* g = sk_GENERAL_NAME_value(gens, i);
    if (g->type == GEN_DNS) ci.sans += (ci.sans.empty() ? "" : ",") + std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(g->d.dNSName)));
  }
  GENERAL_NAMES_free(gens);
  ci.ok = true;
  return ci;
}

// ------------------------------------------------------------ revocation

static std::vector<RevocationResult> check_crl(X509* x, X509* issuer) {
  std::vector<RevocationResult> out;
  auto* dps = static_cast<STACK_OF(DIST_POINT)*>(X509_get_ext_d2i(x, NID_crl_distribution_points, nullptr, nullptr));
  for (int i = 0; dps && i < sk_DIST_POINT_num(dps); ++i) {
    DIST_POINT* dp = sk_DIST_POINT_value(dps, i);
    if (!dp->distpoint || dp->distpoint->type != 0) continue;
    GENERAL_NAMES* names = dp->distpoint->name.fullname;
    for (int j = 0; j < sk_GENERAL_NAME_num(names); ++j) {
      GENERAL_NAME* g = sk_GENERAL_NAME_value(names, j);
      if (g->type != GEN_URI) continue;
      std::string url(reinterpret_cast<const char*>(ASN1_STRING_get0_data(g->d.uniformResourceIdentifier)));
      RevocationResult r{"crl", "error", url};
      auto res = http_fetch("GET", url, "", {});
      if (!res.error.empty() || res.status != 200) {
        r.detail = url + ": fetch failed " + res.error;
        out.push_back(r);
        continue;
      }
      const unsigned char* p = reinterpret_cast<const unsigned char*>(res.body.data());
      X509_CRL* crl = d2i_X509_CRL(nullptr, &p, static_cast<long>(res.body.size()));
      if (!crl) {
        Bio b(BIO_new_mem_buf(res.body.data(), static_cast<int>(res.body.size())));
        crl = PEM_read_bio_X509_CRL(b.get(), nullptr, nullptr, nullptr);
      }
      if (!crl) {
        r.detail = url + ": unparseable CRL";
      } else if (X509_CRL_verify(crl, X509_get0_pubkey(issuer)) != 1) {
        r.detail = url + ": CRL signature does not verify against issuer";
      } else {
        X509_REVOKED* rev = nullptr;
        int64_t next = asn1_to_unix(X509_CRL_get0_nextUpdate(crl));
        if (X509_CRL_get0_by_cert(crl, &rev, x) == 1) {
          r.status = "revoked";
          r.detail = url + ": serial listed, revoked at " + rfc3339(Clock::from_time_t(asn1_to_unix(X509_REVOKED_get0_revocationDate(rev))), false);
        } else {
          r.status = "good";
          r.detail = url;
        }
        if (next && next < unix_now()) r.detail += " (CRL is stale: nextUpdate passed)";
      }
      X509_CRL_free(crl);
      out.push_back(r);
    }
  }
  sk_DIST_POINT_pop_free(dps, DIST_POINT_free);
  return out;
}

static std::vector<RevocationResult> check_ocsp(X509* x, X509* issuer) {
  std::vector<RevocationResult> out;
  STACK_OF(OPENSSL_STRING)* urls = X509_get1_ocsp(x);
  for (int i = 0; urls && i < sk_OPENSSL_STRING_num(urls); ++i) {
    std::string url = sk_OPENSSL_STRING_value(urls, i);
    RevocationResult r{"ocsp", "error", url};
    OCSP_REQUEST* req = OCSP_REQUEST_new();
    OCSP_CERTID* id = OCSP_cert_to_id(nullptr, x, issuer);
    OCSP_CERTID* id_copy = OCSP_CERTID_dup(id);
    OCSP_request_add0_id(req, id);
    OCSP_request_add1_nonce(req, nullptr, -1);  // replay protection
    unsigned char* der = nullptr;
    int n = i2d_OCSP_REQUEST(req, &der);
    std::string body(reinterpret_cast<char*>(der), static_cast<size_t>(n));
    OPENSSL_free(der);
    auto res = http_fetch("POST", url, body, {{"Content-Type", "application/ocsp-request"}});
    OCSP_RESPONSE* resp = nullptr;
    OCSP_BASICRESP* bs = nullptr;
    if (!res.error.empty() || res.status != 200) {
      r.detail = url + ": request failed " + res.error;
    } else {
      const unsigned char* p = reinterpret_cast<const unsigned char*>(res.body.data());
      resp = d2i_OCSP_RESPONSE(nullptr, &p, static_cast<long>(res.body.size()));
      if (!resp || OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL || !(bs = OCSP_response_get1_basic(resp))) {
        r.detail = url + ": unsuccessful OCSP response";
      } else if (OCSP_check_nonce(req, bs) <= 0) {
        r.detail = url + ": nonce mismatch (possible replay)";
      } else {
        X509_STORE* store = X509_STORE_new();
        X509_STORE_add_cert(store, issuer);
        STACK_OF(X509)* certs = sk_X509_new_null();
        sk_X509_push(certs, issuer);
        if (OCSP_basic_verify(bs, certs, store, 0) <= 0) {
          r.detail = url + ": OCSP response signature invalid";
        } else {
          int status, reason;
          ASN1_GENERALIZEDTIME *rev, *thisu, *nextu;
          if (OCSP_resp_find_status(bs, id_copy, &status, &reason, &rev, &thisu, &nextu) != 1) {
            r.detail = url + ": certificate not in response";
          } else if (OCSP_check_validity(thisu, nextu, 300, -1) != 1) {
            r.detail = url + ": response outside validity window";
          } else {
            r.status = status == V_OCSP_CERTSTATUS_GOOD ? "good" : status == V_OCSP_CERTSTATUS_REVOKED ? "revoked" : "unknown";
            r.detail = url;
          }
        }
        sk_X509_free(certs);
        X509_STORE_free(store);
      }
    }
    OCSP_BASICRESP_free(bs);
    OCSP_RESPONSE_free(resp);
    OCSP_CERTID_free(id_copy);
    OCSP_REQUEST_free(req);
    out.push_back(r);
  }
  X509_email_free(urls);
  return out;
}

std::vector<RevocationResult> check_revocation(const std::string& cert_pem, const std::string& issuer_pem) {
  X509p x = x509_from_pem(cert_pem), is = x509_from_pem(issuer_pem);
  if (!x || !is) return {{"-", "error", "cannot parse certificate or issuer"}};
  auto out = check_ocsp(x.get(), is.get());
  auto crl = check_crl(x.get(), is.get());
  out.insert(out.end(), crl.begin(), crl.end());
  if (out.empty()) out.push_back({"-", "unknown", "certificate names no OCSP responder or CRL distribution point"});
  return out;
}

// ------------------------------------------------------------ ACME (RFC 8555)

namespace {
struct Acme {
  json dir;
  std::string nonce, kid, ca;
  Pkey key;
  json jwk;

  static std::string b64u(const std::string& s) { return b64encode(s, true); }

  void make_jwk() {
    BIGNUM *x = nullptr, *y = nullptr;
    EVP_PKEY_get_bn_param(key.get(), OSSL_PKEY_PARAM_EC_PUB_X, &x);
    EVP_PKEY_get_bn_param(key.get(), OSSL_PKEY_PARAM_EC_PUB_Y, &y);
    unsigned char bx[32], by[32];
    BN_bn2binpad(x, bx, 32);
    BN_bn2binpad(y, by, 32);
    BN_free(x);
    BN_free(y);
    // member order matters for the RFC 7638 thumbprint: lexicographic
    jwk = json{{"crv", "P-256"}, {"kty", "EC"},
               {"x", b64u(std::string(reinterpret_cast<char*>(bx), 32))},
               {"y", b64u(std::string(reinterpret_cast<char*>(by), 32))}};
  }
  std::string thumbprint() const {
    unsigned char md[32];
    unsigned int n;
    std::string s = jwk.dump();  // nlohmann sorts keys, no whitespace
    EVP_Digest(s.data(), s.size(), md, &n, EVP_sha256(), nullptr);
    return b64u(std::string(reinterpret_cast<char*>(md), n));
  }
  std::string es256(const std::string& msg) {
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    size_t len = 0;
    EVP_DigestSignInit(c, nullptr, EVP_sha256(), nullptr, key.get());
    EVP_DigestSign(c, nullptr, &len, reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
    std::string der(len, '\0');
    EVP_DigestSign(c, reinterpret_cast<unsigned char*>(der.data()), &len, reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
    EVP_MD_CTX_free(c);
    // JWS wants raw r||s, OpenSSL produces DER ECDSA-Sig-Value
    const unsigned char* p = reinterpret_cast<const unsigned char*>(der.data());
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(len));
    unsigned char rs[64];
    BN_bn2binpad(ECDSA_SIG_get0_r(sig), rs, 32);
    BN_bn2binpad(ECDSA_SIG_get0_s(sig), rs + 32, 32);
    ECDSA_SIG_free(sig);
    return std::string(reinterpret_cast<char*>(rs), 64);
  }
  void refresh_nonce() {
    auto r = http_fetch("HEAD", dir["newNonce"], "", {}, ca);
    nonce = r.headers["replay-nonce"];
  }
  // payload == nullopt -> POST-as-GET (empty payload)
  HttpResult post(const std::string& url, const std::optional<json>& payload) {
    HttpResult last;
    for (int attempt = 0; attempt < 4; ++attempt) {
      if (nonce.empty()) refresh_nonce();
      json prot = {{"alg", "ES256"}, {"nonce", nonce}, {"url", url}};
      if (kid.empty()) prot["jwk"] = jwk;
      else prot["kid"] = kid;
      std::string p64 = b64u(prot.dump()), pl64 = payload ? b64u(payload->dump()) : "";
      json jws = {{"protected", p64}, {"payload", pl64}, {"signature", b64u(es256(p64 + "." + pl64))}};
      auto r = http_fetch("POST", url, jws.dump(), {{"Content-Type", "application/jose+json"}}, ca);
      nonce = r.headers["replay-nonce"];
      last = r;
      if (r.status == 400 && r.body.find("badNonce") != std::string::npos) continue;  // RFC 8555 7.2: retry
      if (r.status == 0) {  // transport error: the nonce may or may not have been consumed
        nonce.clear();
        std::this_thread::sleep_for(std::chrono::milliseconds(100 << attempt));
        continue;
      }
      return r;
    }
    if (last.error.empty()) last.error = "retries exhausted";
    return last;
  }
};

json poll(Acme& a, const std::string& url, const std::string& until, std::string* err) {
  for (int i = 0; i < 100; ++i) {
    auto r = a.post(url, std::nullopt);
    json j = json::parse(r.body, nullptr, false);
    if (j.is_discarded()) { *err = "bad JSON from " + url; return {}; }
    std::string st = j.value("status", "");
    if (st == until) return j;
    if (st == "invalid") { *err = url + " became invalid: " + r.body; return {}; }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  *err = "timeout waiting for " + until + " at " + url;
  return {};
}
}  // namespace

static AcmeResult acme_issue_impl(const std::string& directory_url, const std::string& ca_file, const std::string& cn,
                                  const std::string& key_pem, int challenge_port, const std::string& account_key_path);

AcmeResult acme_issue(const std::string& directory_url, const std::string& ca_file, const std::string& cn,
                      const std::string& key_pem, int challenge_port, const std::string& account_key_path) {
  // a malformed CA response must fail this renewal, not terminate the daemon
  // (an uncaught nlohmann::json exception on the timer thread == std::terminate)
  try {
    return acme_issue_impl(directory_url, ca_file, cn, key_pem, challenge_port, account_key_path);
  } catch (const std::exception& e) {
    AcmeResult r;
    r.error = std::string("ACME protocol error: ") + e.what();
    return r;
  }
}

static AcmeResult acme_issue_impl(const std::string& directory_url, const std::string& ca_file, const std::string& cn,
                                  const std::string& key_pem, int challenge_port, const std::string& account_key_path) {
  AcmeResult res;
  double t0 = mono_us();
  auto fail = [&](std::string m) { res.error = std::move(m); res.ms = (mono_us() - t0) / 1000; return res; };
  Acme a;
  a.ca = ca_file;
  auto d = http_fetch("GET", directory_url, "", {}, ca_file);
  if (!d.error.empty() || d.status != 200) return fail("directory: " + d.error + " status " + std::to_string(d.status));
  a.dir = json::parse(d.body, nullptr, false);
  if (a.dir.is_discarded() || !a.dir.contains("newOrder")) return fail("directory: bad JSON");

  auto acct_pem = read_file(account_key_path);
  if (!acct_pem) {
    acct_pem = gen_ec_key_pem();
    atomic_write(account_key_path, *acct_pem);
  }
  a.key = key_from_pem(*acct_pem);
  a.make_jwk();

  auto acc = a.post(a.dir["newAccount"], json{{"termsOfServiceAgreed", true}});
  if (acc.status != 200 && acc.status != 201) return fail("newAccount: " + std::to_string(acc.status) + " " + acc.error + acc.body);
  a.kid = acc.headers["location"];

  auto ord = a.post(a.dir["newOrder"], json{{"identifiers", json::array({{{"type", "dns"}, {"value", cn}}})}});
  if (ord.status != 201) return fail("newOrder: " + std::to_string(ord.status) + " " + ord.error + ord.body);
  std::string order_url = ord.headers["location"];
  json order = json::parse(ord.body);

  // http-01: serve token -> keyAuthorization for the lifetime of this order
  std::mutex tmu;
  std::map<std::string, std::string> tokens;
  HttpServer chal([&](const HttpRequest& rq) {
    std::lock_guard lk(tmu);
    const std::string pre = "/.well-known/acme-challenge/";
    if (starts_with(rq.path, pre))
      if (auto it = tokens.find(rq.path.substr(pre.size())); it != tokens.end()) return HttpResponse{200, "application/octet-stream", it->second};
    return HttpResponse{404, "text/plain", "not found"};
  });
  std::string err;
  if (!chal.listen("0.0.0.0", challenge_port, &err)) return fail("challenge listener: " + err);
  chal.start();

  for (auto& az : order["authorizations"]) {
    auto ar = a.post(az.get<std::string>(), std::nullopt);
    json authz = json::parse(ar.body, nullptr, false);
    if (authz.value("status", "") == "valid") continue;
    json ch;
    for (auto& c : authz["challenges"])
      if (c["type"] == "http-01") ch = c;
    if (ch.is_null()) return fail("no http-01 challenge offered");
    {
      std::lock_guard lk(tmu);
      std::string tok = ch["token"];
      tokens[tok] = tok + "." + a.thumbprint();
    }
    auto cr = a.post(ch["url"], json::object());
    if (cr.status != 200) return fail("challenge: " + std::to_string(cr.status) + " " + cr.error + cr.body);
    if (poll(a, az, "valid", &err).is_null()) return fail("authorization: " + err);
  }
  chal.stop();

  auto fin = a.post(order["finalize"], json{{"csr", b64encode(make_csr_der(key_pem, cn), true)}});
  if (fin.status != 200) return fail("finalize: " + std::to_string(fin.status) + " " + fin.error + fin.body);
  json done = poll(a, order_url, "valid", &err);
  if (done.is_null()) return fail("order: " + err);
  auto cert = a.post(done["certificate"], std::nullopt);
  if (cert.status != 200) return fail("certificate download: " + std::to_string(cert.status));
  res.ok = true;
  res.cert_chain_pem = cert.body;
  res.ms = (mono_us() - t0) / 1000;
  return res;
}

// ------------------------------------------------------------ manager

CertManager::CertManager(std::string dir, Syslog* log, Reload reload, std::string acme_ca, int challenge_port)
    : dir_(std::move(dir)), log_(log), reload_(std::move(reload)), acme_ca_(std::move(acme_ca)), chal_port_(challenge_port) {
  mkdirs(dir_);
}

void CertManager::install(const std::string& key, const std::string& chain, const std::string& source) {
  std::string err;
  auto ctx = make_server_ctx(chain, key, &err);
  if (!ctx) throw std::runtime_error(err);
  // Don't hand out a certificate before every client considers it valid.
  // Pebble stamps notBefore = time.Now() with no backdating, so a cert
  // installed the instant it is issued was "not yet valid" for clients whose
  // clock read the previous second: 537 of 72k handshakes failed in one 60 s
  // renewal-churn run. The old cert is still valid, so keep serving it until
  // notBefore + margin. (Let's Encrypt backdates 1 h, step-ca 1 min.)
  auto nb = cert_info(chain).not_before;
  int64_t wait = nb + kActivationMarginS - unix_now();
  if (wait > 0) {
    if (wait > 30) throw std::runtime_error("issued certificate is not valid for another " + std::to_string(wait) + "s (CA clock ahead?)");
    if (log_) log_->log(Sev::Info, "CERT_DEFER", "activating new certificate in " + std::to_string(wait) + "s (notBefore)");
    std::this_thread::sleep_for(std::chrono::seconds(wait));
  }
  // key first: a crash between the two writes leaves a new key + old cert,
  // which make_server_ctx rejects at startup -> we fall back to re-issuing
  atomic_write(dir_ + "/server.key", key);
  atomic_write(dir_ + "/server.crt", chain);
  atomic_write(dir_ + "/source", source);
  {
    std::lock_guard lk(mu_);
    cert_pem_ = chain;
    source_ = source;
    info_ = cert_info(chain);
    last_alert_bucket_ = -1;
  }
  reload_(ctx);  // new handshakes use the new cert; established sessions are untouched
}

void CertManager::start_with_existing_or_selfsigned() {
  auto k = read_file(dir_ + "/server.key"), c = read_file(dir_ + "/server.crt");
  if (k && c) {
    std::string err;
    if (auto ctx = make_server_ctx(*c, *k, &err)) {
      std::lock_guard lk(mu_);
      cert_pem_ = *c;
      source_ = read_file(dir_ + "/source").value_or("unknown");
      info_ = cert_info(*c);
      reload_(ctx);
      return;
    }
    if (log_) log_->log(Sev::Err, "CERT_LOAD", "stored certificate/key unusable, generating a new self-signed one");
  }
  std::string key = gen_ec_key_pem();
  install(key, self_signed_pem(key, cn_, 30), "self-signed");
}

AcmeResult CertManager::renew(const std::string& why) {
  std::lock_guard rl(renew_mu_);
  std::string cn, directory;
  {
    std::lock_guard lk(mu_);
    cn = cn_;
    directory = directory_;
  }
  AcmeResult r;
  std::string key = gen_ec_key_pem();  // fresh key per certificate
  if (directory.empty()) {
    r.ok = true;
    r.cert_chain_pem = self_signed_pem(key, cn, 30);
  } else {
    r = acme_issue(directory, acme_ca_, cn, key, chal_port_, dir_ + "/acme-account.key");
  }
  if (r.ok) {
    try {
      install(key, r.cert_chain_pem, directory.empty() ? "self-signed" : "acme:" + directory);
    } catch (const std::exception& e) {
      r.ok = false;
      r.error = e.what();
    }
  }
  std::lock_guard lk(mu_);
  last_ms_ = r.ms;
  if (r.ok) {
    ++renewals_;
    last_error_.clear();
    if (log_)
      log_->log(Sev::Notice, "CERT_RENEWED", "certificate renewed (" + why + "), serial " + info_.serial,
                {{"cert@32473", {{"cn", cn}, {"serial", info_.serial}, {"not-after", rfc3339(Clock::from_time_t(info_.not_after), false)}, {"ms", std::to_string(static_cast<int>(r.ms))}}}});
  } else {
    ++failures_;
    last_error_ = r.error;
    if (log_) log_->log(Sev::Err, "CERT_RENEW_FAILED", "certificate renewal failed: " + r.error);
  }
  return r;
}

int64_t CertManager::seconds_left() const {
  std::lock_guard lk(mu_);
  return info_.not_after - unix_now();
}

void CertManager::tick() {
  int64_t left, before;
  int alert_days;
  bool fresh_failure;
  {
    std::lock_guard lk(mu_);
    left = info_.not_after - unix_now();
    before = renew_before_;
    alert_days = alert_days_;
    fresh_failure = !last_error_.empty();
    // expiry alerts: once per day-bucket while inside the alert window
    int64_t bucket = left / 86400;
    if (left < static_cast<int64_t>(alert_days) * 86400 && bucket != last_alert_bucket_) {
      last_alert_bucket_ = bucket;
      if (log_)
        log_->log(left < 86400 ? Sev::Crit : Sev::Warning, "CERT_EXPIRY",
                  "HTTPS certificate expires in " + std::to_string(left / 3600) + " hours",
                  {{"cert@32473", {{"serial", info_.serial}, {"seconds-left", std::to_string(left)}}}});
    }
  }
  (void)fresh_failure;
  if (left < before) renew("expires in " + std::to_string(left) + "s < renew-before " + std::to_string(before) + "s");
}

std::vector<RevocationResult> CertManager::check_revocation_now() {
  std::string pem;
  {
    std::lock_guard lk(mu_);
    pem = cert_pem_;
  }
  // the chain file is leaf followed by issuer
  auto pos = pem.find("-----BEGIN CERTIFICATE-----", 10);
  if (pos == std::string::npos) return {{"-", "unknown", "no issuer in chain (self-signed)"}};
  return check_revocation(pem.substr(0, pos), pem.substr(pos));
}

std::string CertManager::show() const {
  std::lock_guard lk(mu_);
  int64_t left = info_.not_after - unix_now();
  std::string s;
  s += "Subject:       " + (info_.subject.empty() ? std::string("(empty; identity is in the SAN)") : info_.subject) + "\n";
  s += "Issuer:        " + info_.issuer + "\n";
  s += "Serial:        " + info_.serial + "\n";
  s += "SAN:           " + info_.sans + "\n";
  s += "Valid:         " + rfc3339(Clock::from_time_t(info_.not_before), false) + " .. " + rfc3339(Clock::from_time_t(info_.not_after), false) + "\n";
  s += "Remaining:     " + std::to_string(left) + "s (" + std::to_string(left / 86400) + " days)\n";
  s += "Source:        " + source_ + "\n";
  s += "Renew before:  " + std::to_string(renew_before_) + "s   alert-days " + std::to_string(alert_days_) + "\n";
  s += "Renewals:      " + std::to_string(renewals_) + " ok, " + std::to_string(failures_) + " failed";
  if (renewals_) s += ", last took " + std::to_string(static_cast<int>(last_ms_)) + " ms";
  s += "\n";
  if (!last_error_.empty()) s += "Last error:    " + last_error_ + "\n";
  return s;
}

void CertManager::apply(const Config& c, const std::vector<Change>&) {
  std::lock_guard lk(mu_);
  auto get = [&](const char* k, std::string d) { auto it = c.find(k); return it == c.end() ? d : it->second; };
  cn_ = get("system certificate common-name", get("system hostname", "localhost"));
  directory_ = get("system certificate acme-directory", "");
  renew_before_ = std::stoll(get("system certificate renew-before", std::to_string(30 * 86400)));
  alert_days_ = std::stoi(get("system certificate alert-days", "14"));
}

}  // namespace fw
