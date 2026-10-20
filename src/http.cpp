#include "http.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include "util.hpp"

namespace fw {

static std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
  return s;
}

bool parse_request_head(const std::string& head, HttpRequest& req, size_t* clen, std::string* err) {
  auto fail = [&](const char* m) { if (err) *err = m; return false; };
  size_t eol = head.find("\r\n");
  if (eol == std::string::npos) return fail("no request line");
  std::string line = head.substr(0, eol);
  size_t a = line.find(' '), b = line.rfind(' ');
  if (a == std::string::npos || b == a) return fail("bad request line");
  req.method = line.substr(0, a);
  req.target = line.substr(a + 1, b - a - 1);
  std::string ver = line.substr(b + 1);
  if (ver != "HTTP/1.1" && ver != "HTTP/1.0") return fail("bad version");
  if (req.method.empty() || req.target.empty() || req.target[0] != '/') return fail("bad target");
  auto q = req.target.find('?');
  req.path = req.target.substr(0, q);
  req.query = q == std::string::npos ? "" : req.target.substr(q + 1);
  size_t pos = eol + 2;
  *clen = 0;
  while (pos < head.size()) {
    size_t e = head.find("\r\n", pos);
    if (e == std::string::npos) return fail("unterminated header");
    if (e == pos) break;  // blank line
    std::string h = head.substr(pos, e - pos);
    pos = e + 2;
    auto colon = h.find(':');
    if (colon == std::string::npos || colon == 0) return fail("bad header");
    std::string name = lower(h.substr(0, colon));
    std::string val = trim(h.substr(colon + 1));
    if (name == "content-length") {
      if (req.headers.count(name)) return fail("duplicate content-length");  // request-smuggling guard
      if (val.empty() || val.size() > 9 || val.find_first_not_of("0123456789") != std::string::npos)
        return fail("bad content-length");
      *clen = std::stoul(val);
    }
    if (name == "transfer-encoding") return fail("transfer-encoding not supported");
    req.headers[name] = val;
    if (req.headers.size() > 64) return fail("too many headers");
  }
  return true;
}

SslCtxPtr make_server_ctx(const std::string& cert_pem, const std::string& key_pem, std::string* err) {
  SslCtxPtr ctx(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
  BIO* cb = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
  X509* leaf = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
  bool ok = leaf && SSL_CTX_use_certificate(ctx.get(), leaf) == 1;
  X509_free(leaf);
  // remaining certs in the PEM are the chain
  while (ok) {
    X509* extra = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
    if (!extra) break;
    SSL_CTX_add_extra_chain_cert(ctx.get(), extra);  // takes ownership
  }
  ERR_clear_error();
  BIO_free(cb);
  BIO* kb = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
  EVP_PKEY* k = PEM_read_bio_PrivateKey(kb, nullptr, nullptr, nullptr);
  BIO_free(kb);
  ok = ok && k && SSL_CTX_use_PrivateKey(ctx.get(), k) == 1 && SSL_CTX_check_private_key(ctx.get()) == 1;
  EVP_PKEY_free(k);
  if (!ok) {
    if (err) *err = "certificate/key load failed";
    return nullptr;
  }
  return ctx;
}

void HttpServer::set_ctx(SslCtxPtr ctx) {
  std::lock_guard lk(mu_);
  ctx_ = std::move(ctx);
  ++ctx_swaps;
}

SslCtxPtr HttpServer::ctx() const {
  std::lock_guard lk(mu_);
  return ctx_;
}

bool HttpServer::listen(const std::string& addr, int port, std::string* err) {
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(static_cast<uint16_t>(port));
  inet_pton(AF_INET, addr.c_str(), &sa.sin_addr);
  if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0 || ::listen(fd, 512) != 0) {
    if (err) *err = std::string("bind/listen: ") + strerror(errno);
    ::close(fd);
    return false;
  }
  socklen_t sl = sizeof sa;
  getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &sl);
  int old = listen_fd_.exchange(fd);
  port_ = ntohs(sa.sin_port);
  if (old >= 0) ::close(old);  // accept loop picks up the new fd on its next poll
  return true;
}

void HttpServer::start() {
  running_ = true;
  th_ = std::thread([this] { accept_loop(); });
}

void HttpServer::stop() {
  if (!running_.exchange(false)) return;
  if (th_.joinable()) th_.join();
  int fd = listen_fd_.exchange(-1);
  if (fd >= 0) ::close(fd);
  {
    std::lock_guard lk(fds_mu_);
    for (int c : fds_) ::shutdown(c, SHUT_RDWR);  // wakes threads blocked in read
  }
  for (int i = 0; i < 500 && active_ > 0; ++i) usleep(10000);
}

void HttpServer::accept_loop() {
  while (running_) {
    int lfd = listen_fd_.load();
    if (lfd < 0) { usleep(50000); continue; }
    pollfd p{lfd, POLLIN, 0};
    if (poll(&p, 1, 100) <= 0 || !(p.revents & POLLIN)) continue;
    sockaddr_in peer{};
    socklen_t sl = sizeof peer;
    int fd = ::accept4(lfd, reinterpret_cast<sockaddr*>(&peer), &sl, SOCK_CLOEXEC);
    if (fd < 0) continue;
    char ip[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
    ++connections;
    ++active_;
    {
      std::lock_guard lk(fds_mu_);
      fds_.insert(fd);
    }
    // the ctx is captured per connection: a later set_ctx() affects only new
    // connections; this one keeps its SSL_CTX alive via the shared_ptr
    std::thread([this, fd, c = ctx(), s = std::string(ip)] {
      serve(fd, c, s);
      {
        std::lock_guard lk(fds_mu_);
        fds_.erase(fd);
      }
      ::close(fd);
      --active_;
    }).detach();
  }
}

namespace {
struct Conn {
  int fd;
  SSL* ssl = nullptr;
  int read(char* b, int n) { return ssl ? SSL_read(ssl, b, n) : static_cast<int>(::recv(fd, b, n, 0)); }
  bool write_all(const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
      int n = ssl ? SSL_write(ssl, s.data() + off, static_cast<int>(s.size() - off))
                  : static_cast<int>(::send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL));
      if (n <= 0) return false;
      off += static_cast<size_t>(n);
    }
    return true;
  }
};

const char* reason(int s) {
  switch (s) {
    case 200: return "OK";
    case 201: return "Created";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Payload Too Large";
    case 422: return "Unprocessable Entity";
    default: return s >= 500 ? "Internal Server Error" : "Status";
  }
}
}  // namespace

void HttpServer::serve(int fd, SslCtxPtr ctx, std::string peer) {
  timeval tv{30, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
  Conn c{fd};
  if (ctx) {
    c.ssl = SSL_new(ctx.get());
    SSL_set_fd(c.ssl, fd);
    if (SSL_accept(c.ssl) != 1) {
      ++handshake_failures;
      SSL_free(c.ssl);
      return;
    }
  }
  std::string buf;
  char tmp[16384];
  bool keep = true;
  while (keep && running_) {
    size_t he;
    while ((he = buf.find("\r\n\r\n")) == std::string::npos) {
      if (buf.size() > 65536) { keep = false; break; }
      int n = c.read(tmp, sizeof tmp);
      if (n <= 0) { keep = false; break; }
      buf.append(tmp, static_cast<size_t>(n));
    }
    if (!keep) break;
    HttpRequest req;
    size_t clen = 0;
    std::string err;
    HttpResponse resp;
    bool ok = parse_request_head(buf.substr(0, he + 4), req, &clen, &err);
    if (ok && clen > (1u << 20)) { ok = false; resp.status = 413; }
    if (ok) {
      size_t need = he + 4 + clen;
      while (buf.size() < need) {
        int n = c.read(tmp, sizeof tmp);
        if (n <= 0) { keep = false; break; }
        buf.append(tmp, static_cast<size_t>(n));
      }
      if (!keep) break;
      req.body = buf.substr(he + 4, clen);
      buf.erase(0, need);
      req.peer = peer;
      ++requests;
      try {
        resp = handler_(req);
      } catch (const std::exception& e) {
        resp = {500, "application/json", std::string("{\"error\":\"internal\"}")};
      }
      if (req.headers["connection"] == "close") keep = false;
    } else {
      if (resp.status == 200) resp.status = 400;
      resp.body = "{\"error\":\"bad request\"}";
      keep = false;
    }
    std::string out = "HTTP/1.1 " + std::to_string(resp.status) + " " + reason(resp.status) + "\r\n";
    out += "Content-Type: " + resp.content_type + "\r\nContent-Length: " + std::to_string(resp.body.size()) + "\r\n";
    for (auto& [k, v] : resp.headers) out += k + ": " + v + "\r\n";
    out += keep ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n";
    out += resp.body;
    if (!c.write_all(out)) break;
  }
  if (c.ssl) {
    SSL_shutdown(c.ssl);
    SSL_free(c.ssl);
  }
}

// ---------------- client ----------------

HttpResult http_fetch(const std::string& method, const std::string& url, const std::string& body,
                      const std::map<std::string, std::string>& headers, const std::string& ca_file) {
  HttpResult r;
  bool tls;
  std::string rest;
  if (starts_with(url, "https://")) { tls = true; rest = url.substr(8); }
  else if (starts_with(url, "http://")) { tls = false; rest = url.substr(7); }
  else { r.error = "unsupported url"; return r; }
  auto slash = rest.find('/');
  std::string hostport = rest.substr(0, slash), path = slash == std::string::npos ? "/" : rest.substr(slash);
  std::string host = hostport, port = tls ? "443" : "80";
  if (auto c = hostport.rfind(':'); c != std::string::npos) { host = hostport.substr(0, c); port = hostport.substr(c + 1); }

  addrinfo hints{}, *ai = nullptr;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host.c_str(), port.c_str(), &hints, &ai) != 0 || !ai) { r.error = "resolve " + host; return r; }
  int fd = ::socket(ai->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
  timeval tv{10, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
  int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
  freeaddrinfo(ai);
  if (rc != 0) { r.error = "connect " + hostport + ": " + strerror(errno); ::close(fd); return r; }

  SSL_CTX* ctx = nullptr;
  Conn c{fd};
  if (tls) {
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ca_file.empty()) SSL_CTX_load_verify_locations(ctx, ca_file.c_str(), nullptr);
    else SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    c.ssl = SSL_new(ctx);
    SSL_set_fd(c.ssl, fd);
    SSL_set_tlsext_host_name(c.ssl, host.c_str());
    SSL_set1_host(c.ssl, host.c_str());
    if (SSL_connect(c.ssl) != 1) {
      r.error = "tls handshake with " + hostport + " failed (verify=" +
                X509_verify_cert_error_string(SSL_get_verify_result(c.ssl)) + ")";
      SSL_free(c.ssl);
      SSL_CTX_free(ctx);
      ::close(fd);
      return r;
    }
  }
  std::string req = method + " " + path + " HTTP/1.1\r\nHost: " + hostport + "\r\nConnection: close\r\nUser-Agent: fw-mgmtd\r\n";
  for (auto& [k, v] : headers) req += k + ": " + v + "\r\n";
  if (!body.empty() || method == "POST") req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
  req += "\r\n" + body;
  std::string resp;
  if (c.write_all(req)) {
    char tmp[16384];
    int n;
    while ((n = c.read(tmp, sizeof tmp)) > 0) resp.append(tmp, static_cast<size_t>(n));
  }
  if (c.ssl) SSL_free(c.ssl);
  if (ctx) SSL_CTX_free(ctx);
  ::close(fd);

  auto he = resp.find("\r\n\r\n");
  if (he == std::string::npos || resp.size() < 12) { r.error = "bad response"; return r; }
  r.status = atoi(resp.c_str() + 9);
  size_t pos = resp.find("\r\n") + 2;
  while (pos < he) {
    size_t e = resp.find("\r\n", pos);
    auto h = resp.substr(pos, e - pos);
    pos = e + 2;
    auto colon = h.find(':');
    if (colon != std::string::npos) r.headers[lower(h.substr(0, colon))] = trim(h.substr(colon + 1));
  }
  std::string raw = resp.substr(he + 4);
  if (lower(r.headers["transfer-encoding"]) == "chunked") {
    size_t p = 0;
    while (p < raw.size()) {
      size_t e = raw.find("\r\n", p);
      if (e == std::string::npos) break;
      size_t len = std::stoul(raw.substr(p, e - p), nullptr, 16);
      if (len == 0) break;
      r.body += raw.substr(e + 2, len);
      p = e + 2 + len + 2;
    }
  } else {
    r.body = std::move(raw);
  }
  return r;
}

}  // namespace fw
