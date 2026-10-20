// Minimal HTTP/1.1 over OpenSSL: a server (REST API, ACME http-01 responder)
// whose SSL_CTX can be swapped at runtime, and a blocking client (ACME, OCSP,
// CRL fetch). Deliberately small: one thread per connection, keep-alive,
// Content-Length bodies only on the server side.
#pragma once
#include <openssl/ssl.h>

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace fw {

struct HttpRequest {
  std::string method, target, path, query;
  std::map<std::string, std::string> headers;  // lower-cased names
  std::string body;
  std::string peer;
};

struct HttpResponse {
  int status = 200;
  std::string content_type = "application/json";
  std::string body;
  std::vector<std::pair<std::string, std::string>> headers;
};

// Parses the request head (everything up to and including CRLFCRLF).
// Returns false on malformed input. Exposed for fuzzing.
bool parse_request_head(const std::string& head, HttpRequest& req, size_t* content_length, std::string* err);

using SslCtxPtr = std::shared_ptr<SSL_CTX>;
SslCtxPtr make_server_ctx(const std::string& cert_pem, const std::string& key_pem, std::string* err);

class HttpServer {
 public:
  using Handler = std::function<HttpResponse(const HttpRequest&)>;
  explicit HttpServer(Handler h) : handler_(std::move(h)) {}
  ~HttpServer() { stop(); }

  // ctx == nullptr -> plain HTTP
  void set_ctx(SslCtxPtr ctx);
  SslCtxPtr ctx() const;
  // (Re)binds; safe to call while running (config change of the port).
  bool listen(const std::string& addr, int port, std::string* err);
  void start();
  void stop();
  int port() const { return port_.load(); }

  std::atomic<uint64_t> connections{0}, handshake_failures{0}, requests{0}, ctx_swaps{0};

 private:
  void accept_loop();
  void serve(int fd, SslCtxPtr ctx, std::string peer);

  Handler handler_;
  mutable std::mutex mu_;
  SslCtxPtr ctx_;
  std::atomic<int> listen_fd_{-1}, port_{0};
  std::atomic<bool> running_{false};
  std::atomic<int> active_{0};
  std::mutex fds_mu_;
  std::set<int> fds_;  // live connections, shut down on stop() so no thread outlives us
  std::thread th_;
};

struct HttpResult {
  int status = 0;
  std::map<std::string, std::string> headers;  // lower-cased
  std::string body;
  std::string error;  // transport error
};

// url: http://host[:port]/path or https://... ; ca_file used to verify https.
HttpResult http_fetch(const std::string& method, const std::string& url, const std::string& body,
                      const std::map<std::string, std::string>& headers, const std::string& ca_file = "");

}  // namespace fw
