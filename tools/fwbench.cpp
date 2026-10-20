// Measurement harness. Every number in results/ comes from one of these.
//   fwbench commit DIR [iters]                 commit / rollback latency vs config size (in-process)
//   fwbench ssh PORT USER KEY [iters]          CLI command round-trip over a live SSH shell
//   fwbench https-load PORT CA SECONDS THREADS TOKEN RENEW_EVERY_MS
//                                              new-connection + keep-alive load while certs are renewed
//   fwbench api-commit-loop PORT CA TOKEN      sequential API commits, prints each acknowledged id (crash test)
#include <arpa/inet.h>
#include <libssh/libssh.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <iostream>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
#include <thread>
#include <vector>

#include "certmgr.hpp"
#include "config.hpp"
#include "http.hpp"
#include "store.hpp"
#include "util.hpp"

using namespace fw;
using json = nlohmann::json;

static double pct(std::vector<double> v, double p) {
  if (v.empty()) return 0;
  std::sort(v.begin(), v.end());
  size_t i = static_cast<size_t>(p / 100.0 * static_cast<double>(v.size() - 1) + 0.5);
  return v[std::min(i, v.size() - 1)];
}

static void summary(const char* what, const std::vector<double>& v, const char* unit = "us") {
  printf("%-34s n=%-5zu p50=%9.1f  p90=%9.1f  p99=%9.1f  max=%9.1f %s\n", what, v.size(), pct(v, 50), pct(v, 90), pct(v, 99),
         v.empty() ? 0.0 : *std::max_element(v.begin(), v.end()), unit);
}

// ------------------------------------------------------------------ commit

static Config sized_config(size_t leaves) {
  Config c;
  auto set = [&](const std::string& s) { config_set(c, *tokenize(s)); };
  set("system hostname bench");
  set("system login user admin role admin");
  set("system login user admin ssh-key \"ssh-ed25519 AAAA\"");
  size_t rule = 1;
  while (c.size() < leaves) {
    auto r = std::to_string(rule++);
    set("firewall rule " + r + " action accept");
    set("firewall rule " + r + " source 10." + std::to_string(rule % 250) + ".0.0/16");
    set("firewall rule " + r + " protocol tcp");
    set("firewall rule " + r + " port " + std::to_string(1 + rule % 65000));
  }
  return c;
}

static int cmd_commit(const std::string& dir, int iters) {
  printf("# commit latency: one-leaf change on an N-leaf config, %d iterations each; fsync on every commit\n", iters);
  for (size_t n : {100, 1000, 10000}) {
    std::string d = dir + "/n" + std::to_string(n);
    ConfigStore s(d, nullptr);
    s.open(sized_config(n));
    std::vector<double> tot, val, per, rb;
    for (int i = 0; i < iters; ++i) {
      auto [c, id] = s.snapshot();
      c["system hostname"] = "h" + std::to_string(i);
      auto r = s.commit(c, id, {"bench", "bench"}, "");
      if (!r.ok) { fprintf(stderr, "commit failed: %s\n", r.error.c_str()); return 1; }
      tot.push_back(r.us_total);
      val.push_back(r.us_validate);
      per.push_back(r.us_persist);
    }
    for (int i = 0; i < iters; ++i) {
      double t0 = mono_us();
      auto old = s.rollback_config(1);
      auto r = s.commit(*old, s.running_id(), {"bench", "bench"}, "rollback 1");
      rb.push_back(mono_us() - t0);
      if (!r.ok) return 1;
    }
    printf("N=%zu leaves (%zu bytes on disk)\n", n, to_set_lines(s.snapshot().first).size());
    summary("  commit total", tot);
    summary("    validate+diff", val);
    summary("    persist (write+fsync+rename)", per);
    summary("  rollback 1 (load + commit)", rb);
  }
  return 0;
}

// ------------------------------------------------------------------ ssh

static int cmd_ssh(int port, const std::string& user, const std::string& keyfile, int iters) {
  double t0 = mono_us();
  ssh_session s = ssh_new();
  int verb = SSH_LOG_NOLOG;
  ssh_options_set(s, SSH_OPTIONS_HOST, "127.0.0.1");
  ssh_options_set(s, SSH_OPTIONS_PORT, &port);
  ssh_options_set(s, SSH_OPTIONS_USER, user.c_str());
  ssh_options_set(s, SSH_OPTIONS_LOG_VERBOSITY, &verb);
  if (ssh_connect(s) != SSH_OK) { fprintf(stderr, "connect: %s\n", ssh_get_error(s)); return 1; }
  ssh_key k;
  if (ssh_pki_import_privkey_file(keyfile.c_str(), nullptr, nullptr, nullptr, &k) != SSH_OK) return 1;
  if (ssh_userauth_publickey(s, nullptr, k) != SSH_AUTH_SUCCESS) { fprintf(stderr, "auth failed\n"); return 1; }
  ssh_channel ch = ssh_channel_new(s);
  ssh_channel_open_session(ch);
  ssh_channel_request_shell(ch);  // no pty: no echo, plain prompts
  double t_login = mono_us() - t0;
  std::string buf;
  auto read_until = [&](const std::string& marker) {
    char b[65536];
    while (buf.find(marker) == std::string::npos) {
      int n = ssh_channel_read(ch, b, sizeof b, 0);
      if (n <= 0) return false;
      buf.append(b, static_cast<size_t>(n));
    }
    buf.erase(0, buf.find(marker) + marker.size());
    return true;
  };
  std::string op = user + "@fw> ", cfg = user + "@fw# ";
  read_until(op);
  auto run = [&](const std::string& cmd, const std::string& prompt) {
    double a = mono_us();
    std::string line = cmd + "\n";
    ssh_channel_write(ch, line.data(), static_cast<uint32_t>(line.size()));
    if (!read_until(prompt)) { fprintf(stderr, "lost session\n"); exit(1); }
    return mono_us() - a;
  };
  printf("# CLI over SSH, persistent shell session, %d iterations; login (TCP+kex+pubkey auth+shell) took %.1f ms\n",
         iters, t_login / 1000);
  std::vector<double> show, showlic, set, commit;
  for (int i = 0; i < iters; ++i) show.push_back(run("show configuration system hostname", op));
  for (int i = 0; i < iters; ++i) showlic.push_back(run("show license", op));
  run("configure", cfg);
  for (int i = 0; i < iters; ++i) {
    set.push_back(run("set system hostname bench-" + std::to_string(i), cfg));
    commit.push_back(run("commit", cfg));
  }
  run("exit", op);
  summary("show configuration system hostname", show);
  summary("show license", showlic);
  summary("set (config mode)", set);
  summary("commit (1 change, fsync)", commit);
  ssh_channel_close(ch);
  ssh_channel_free(ch);
  ssh_disconnect(s);
  ssh_free(s);
  ssh_key_free(k);

  // fresh connection per command, like a script doing `ssh fw 'show license'`
  std::vector<double> oneshot;
  for (int i = 0; i < std::min(iters, 50); ++i) {
    double a = mono_us();
    ssh_session s2 = ssh_new();
    ssh_options_set(s2, SSH_OPTIONS_HOST, "127.0.0.1");
    ssh_options_set(s2, SSH_OPTIONS_PORT, &port);
    ssh_options_set(s2, SSH_OPTIONS_USER, user.c_str());
    ssh_options_set(s2, SSH_OPTIONS_LOG_VERBOSITY, &verb);
    ssh_key k2;
    ssh_pki_import_privkey_file(keyfile.c_str(), nullptr, nullptr, nullptr, &k2);
    if (ssh_connect(s2) != SSH_OK || ssh_userauth_publickey(s2, nullptr, k2) != SSH_AUTH_SUCCESS) return 1;
    ssh_channel c2 = ssh_channel_new(s2);
    ssh_channel_open_session(c2);
    ssh_channel_request_exec(c2, "show license");
    char b[4096];
    while (ssh_channel_read(c2, b, sizeof b, 0) > 0) {}
    ssh_channel_close(c2);
    ssh_channel_free(c2);
    ssh_disconnect(s2);
    ssh_free(s2);
    ssh_key_free(k2);
    oneshot.push_back(mono_us() - a);
  }
  summary("one-shot exec (connect..close)", oneshot);
  return 0;
}

// ------------------------------------------------------------------ https load

static thread_local std::string t_verify_why;
static int verify_cb(int ok, X509_STORE_CTX* x) {
  if (!ok) {
    X509* c = X509_STORE_CTX_get_current_cert(x);
    char subj[256] = "", nb[64] = "";
    if (c) {
      X509_NAME_oneline(X509_get_subject_name(c), subj, sizeof subj);
      BIO* b = BIO_new(BIO_s_mem());
      ASN1_TIME_print(b, X509_get0_notBefore(c));
      BIO_read(b, nb, sizeof nb - 1);
      BIO_free(b);
    }
    char now[64];
    time_t t = time(nullptr);
    strftime(now, sizeof now, "%H:%M:%S", gmtime(&t));
    t_verify_why = std::string(X509_verify_cert_error_string(X509_STORE_CTX_get_error(x))) + " depth=" +
                   std::to_string(X509_STORE_CTX_get_error_depth(x)) + " subject=" + subj + " notBefore=" + nb +
                   " client-now=" + now;
  }
  return ok;
}

struct TlsClient {
  SSL_CTX* ctx;
  explicit TlsClient(const std::string& ca) {
    ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_load_verify_locations(ctx, ca.c_str(), nullptr);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);
  }
  struct Conn {
    int fd = -1;
    SSL* ssl = nullptr;
    std::string serial, why;
  };
  bool connect(int port, Conn& c) {
    c.fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    int one = 1;
    setsockopt(c.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    timeval tv{5, 0};
    setsockopt(c.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (::connect(c.fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) return false;
    c.ssl = SSL_new(ctx);
    SSL_set_fd(c.ssl, c.fd);
    SSL_set_tlsext_host_name(c.ssl, "localhost");
    SSL_set1_host(c.ssl, "localhost");
    t_verify_why.clear();
    int rc = SSL_connect(c.ssl);
    if (rc != 1 && !t_verify_why.empty()) c.why = t_verify_why;
    X509* peer = SSL_get1_peer_certificate(c.ssl);
    if (peer) {
      BIGNUM* bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(peer), nullptr);
      char* h = BN_bn2hex(bn);
      c.serial = h;
      OPENSSL_free(h);
      BN_free(bn);
      if (rc != 1 && c.why.empty()) {
        // why did verification fail? keep the verify code and the cert's validity window
        char nb[64] = "", now[64] = "";
        BIO* b = BIO_new(BIO_s_mem());
        ASN1_TIME_print(b, X509_get0_notBefore(peer));
        BIO_read(b, nb, sizeof nb - 1);
        BIO_free(b);
        time_t t = time(nullptr);
        strftime(now, sizeof now, "%b %e %H:%M:%S %Y GMT", gmtime(&t));
        c.why = std::string(X509_verify_cert_error_string(SSL_get_verify_result(c.ssl))) + " serial=" + c.serial +
                " notBefore=" + nb + " client-now=" + now;
      }
      X509_free(peer);
    }
    return rc == 1;
  }
  static bool get(Conn& c, const std::string& path, const std::string& token, bool keepalive, std::string* body = nullptr) {
    std::string req = "GET " + path + " HTTP/1.1\r\nHost: localhost\r\n" +
                      (token.empty() ? "" : "Authorization: Bearer " + token + "\r\n") +
                      (keepalive ? "" : "Connection: close\r\n") + "\r\n";
    if (SSL_write(c.ssl, req.data(), static_cast<int>(req.size())) <= 0) return false;
    std::string resp;
    char b[8192];
    size_t need = std::string::npos;
    while (true) {
      int n = SSL_read(c.ssl, b, sizeof b);
      if (n <= 0) break;
      resp.append(b, static_cast<size_t>(n));
      auto he = resp.find("\r\n\r\n");
      if (he != std::string::npos && need == std::string::npos) {
        auto cl = resp.find("Content-Length: ");
        need = he + 4 + std::stoul(resp.substr(cl + 16));
      }
      if (need != std::string::npos && resp.size() >= need) break;
    }
    if (body && need != std::string::npos) *body = resp.substr(resp.find("\r\n\r\n") + 4);
    return resp.rfind("HTTP/1.1 200", 0) == 0;
  }
  static void close(Conn& c) {
    if (c.ssl) { SSL_shutdown(c.ssl); SSL_free(c.ssl); }
    if (c.fd >= 0) ::close(c.fd);
  }
};

static int cmd_https_load(int port, const std::string& ca, int seconds, int threads, const std::string& token, int renew_ms) {
  TlsClient cl(ca);
  std::atomic<bool> stop{false};
  std::atomic<uint64_t> ok{0}, fail{0}, ka_ok{0}, ka_fail{0};
  std::mutex mu;
  std::map<std::string, uint64_t> serials;  // cert serial -> handshakes that saw it
  std::vector<double> lat;
  std::vector<std::string> errors;
  std::vector<std::thread> th;
  for (int t = 0; t < threads; ++t)
    th.emplace_back([&] {
      std::vector<double> mine;
      while (!stop) {
        double a = mono_us();
        TlsClient::Conn c;
        bool good = cl.connect(port, c) && TlsClient::get(c, "/api/v1/health", "", false);
        if (good) {
          ++ok;
          mine.push_back(mono_us() - a);
          std::lock_guard lk(mu);
          ++serials[c.serial];
        } else {
          ++fail;
          std::lock_guard lk(mu);
          if (errors.size() < 5) errors.push_back(c.why.empty() ? ERR_error_string(ERR_get_error(), nullptr) : c.why);
        }
        TlsClient::close(c);
      }
      std::lock_guard lk(mu);
      lat.insert(lat.end(), mine.begin(), mine.end());
    });
  // long-lived keep-alive connections opened before the first renewal: they must survive every reload
  for (int t = 0; t < 2; ++t)
    th.emplace_back([&] {
      TlsClient::Conn c;
      if (!cl.connect(port, c)) { ++ka_fail; return; }
      while (!stop) {
        if (TlsClient::get(c, "/api/v1/health", "", true)) ++ka_ok;
        else { ++ka_fail; break; }
        usleep(2000);
      }
      TlsClient::close(c);
    });
  int renewals = 0, renew_fail = 0;
  std::vector<double> renew_ms_v;
  double end = mono_us() + seconds * 1e6, next = mono_us() + renew_ms * 1000.0;
  while (mono_us() < end) {
    usleep(20000);
    if (renew_ms > 0 && mono_us() >= next) {
      next = mono_us() + renew_ms * 1000.0;
      json body = {{"command", "request certificate renew"}};
      double a = mono_us();
      auto r = http_fetch("POST", "https://localhost:" + std::to_string(port) + "/api/v1/cli", body.dump(),
                          {{"Authorization", "Bearer " + token}, {"Content-Type", "application/json"}}, ca);
      renew_ms_v.push_back((mono_us() - a) / 1000);
      if (r.status == 200 && r.body.find("renewed") != std::string::npos) ++renewals;
      else { ++renew_fail; fprintf(stderr, "renew failed: %d %s %s\n", r.status, r.error.c_str(), r.body.c_str()); }
    }
  }
  stop = true;
  for (auto& t : th) t.join();
  printf("# HTTPS load: %d threads x new TLS connection per request for %ds, cert renewed every %d ms via ACME\n", threads, seconds, renew_ms);
  printf("requests ok=%llu failed=%llu   keep-alive ok=%llu failed=%llu   renewals ok=%d failed=%d   distinct server certs seen=%zu\n",
         (unsigned long long)ok.load(), (unsigned long long)fail.load(), (unsigned long long)ka_ok.load(),
         (unsigned long long)ka_fail.load(), renewals, renew_fail, serials.size());
  summary("request (connect+TLS+GET+close)", lat);
  if (!renew_ms_v.empty()) summary("ACME renewal (API round trip)", renew_ms_v, "ms");
  for (auto& e : errors) printf("error: %s\n", e.c_str());
  return fail == 0 && ka_fail == 0 && renew_fail == 0 ? 0 : 1;
}

// ------------------------------------------------------------------ crash test client

static int cmd_api_commit_loop(int port, const std::string& ca, const std::string& token) {
  std::string base = "https://localhost:" + std::to_string(port);
  std::map<std::string, std::string> h = {{"Authorization", "Bearer " + token}, {"Content-Type", "application/json"}};
  auto g = http_fetch("GET", base + "/api/v1/config", "", h, ca);
  if (g.status != 200) return 1;
  uint64_t id = json::parse(g.body)["commit"];
  setvbuf(stdout, nullptr, _IOLBF, 0);
  for (;;) {
    json b = {{"base", id}, {"set", {"system hostname crash-" + std::to_string(id + 1)}}};
    auto r = http_fetch("POST", base + "/api/v1/config", b.dump(), h, ca);
    if (r.status != 200) return 0;  // daemon died: stop; the last printed id is the last acknowledged one
    id = json::parse(r.body)["commit"];
    printf("acked %llu crash-%llu\n", (unsigned long long)id, (unsigned long long)id);
  }
}

int main(int argc, char** argv) {
  std::vector<std::string> a(argv + 1, argv + argc);
  if (a.size() >= 2 && a[0] == "commit") return cmd_commit(a[1], a.size() > 2 ? std::stoi(a[2]) : 200);
  if (a.size() >= 4 && a[0] == "ssh") return cmd_ssh(std::stoi(a[1]), a[2], a[3], a.size() > 4 ? std::stoi(a[4]) : 200);
  if (a.size() >= 7 && a[0] == "https-load")
    return cmd_https_load(std::stoi(a[1]), a[2], std::stoi(a[3]), std::stoi(a[4]), a[5], std::stoi(a[6]));
  if (a.size() >= 4 && a[0] == "api-commit-loop") return cmd_api_commit_loop(std::stoi(a[1]), a[2], a[3]);
  if (a.size() >= 3 && a[0] == "revcheck") {
    auto c = read_file(a[1]), i = read_file(a[2]);
    if (!c || !i) return 2;
    double t0 = mono_us();
    auto rs = check_revocation(*c, *i);
    for (auto& r : rs) printf("%s: %s  %s\n", r.method.c_str(), r.status.c_str(), r.detail.c_str());
    printf("checked in %.1f ms\n", (mono_us() - t0) / 1000);
    return 0;
  }
  std::cerr << "usage: see header of tools/fwbench.cpp\n";
  return 2;
}
